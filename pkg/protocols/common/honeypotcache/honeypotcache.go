package honeypotcache

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bluele/gcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// cacheItem holds per-host match data.
type cacheItem struct {
	mu            sync.Mutex
	uniqueMatches map[string]struct{}
}

// Cache tracks per-host template match data for honeypot detection.
type Cache struct {
	mu             sync.RWMutex
	matches        gcache.Cache
	totalTemplates atomic.Int32
	maxHostMatch   int
	disabled       bool
}

// New creates a Cache. maxHostMatch is the absolute count threshold (e.g. 30).
// Pass disabled=true to create a no-op cache when -no-honeypot is set.
func New(maxHostMatch int, disabled bool) *Cache {
	return &Cache{
		matches:      gcache.New(1000).ARC().Build(),
		maxHostMatch: maxHostMatch,
		disabled:     disabled,
	}
}

// SetTotalTemplates records the total number of templates loaded.
// Must be called after the template store is built, before scanning begins.
func (c *Cache) SetTotalTemplates(n int) {
	if c == nil {
		return
	}
	c.totalTemplates.Store(int32(n))
}

// MarkMatch records that templateID matched on the host derived from ctx.
func (c *Cache) MarkMatch(ctx *contextargs.Context, templateID string) {
	if c == nil || c.disabled || ctx == nil || ctx.MetaInput == nil {
		return
	}
	key := normalizeHost(ctx.MetaInput.Input)

	c.mu.Lock()
	raw, err := c.matches.GetIFPresent(key)
	var item *cacheItem
	if err != nil {
		item = &cacheItem{uniqueMatches: make(map[string]struct{})}
		_ = c.matches.Set(key, item)
	} else {
		item = raw.(*cacheItem)
	}
	// Acquire item lock BEFORE releasing cache lock — prevents eviction+reinsertion race.
	item.mu.Lock()
	c.mu.Unlock()
	defer item.mu.Unlock()

	item.uniqueMatches[templateID] = struct{}{}
}

// Check returns true if the host has been flagged as a honeypot.
func (c *Cache) Check(ctx *contextargs.Context) bool {
	if c == nil || c.disabled || ctx == nil || ctx.MetaInput == nil {
		return false
	}
	key := normalizeHost(ctx.MetaInput.Input)

	c.mu.RLock()
	raw, err := c.matches.GetIFPresent(key)
	c.mu.RUnlock()
	if err != nil {
		return false
	}

	item := raw.(*cacheItem)
	item.mu.Lock()
	count := len(item.uniqueMatches)
	item.mu.Unlock()

	// Absolute threshold — always takes precedence when configured.
	if c.maxHostMatch > 0 {
		return count >= c.maxHostMatch
	}

	// Percentage threshold — only used when no absolute limit is set.
	// Requires at least 20 templates to avoid false-positives on small targeted scans
	// where a few genuine vulnerabilities could accidentally hit the 50% mark.
	const minTotalForPct = 20
	total := int(c.totalTemplates.Load())
	if total >= minTotalForPct && count > 0 {
		pct := (count * 100) / total
		if pct >= 50 {
			return true
		}
	}

	return false
}

// CheckSignature scans content for known honeypot indicator patterns.
// Returns (true, signatureName) if a known pattern matches.
func CheckSignature(content string) (bool, string) {
	for _, sig := range signatures {
		if sig.re.MatchString(content) {
			return true, sig.name
		}
	}
	return false, ""
}

// signature pairs a human-readable name with a compiled regex.
type signature struct {
	name string
	re   *regexp.Regexp
}

// signatures is the honeypot pattern list.
// Intentionally excludes "canary" (false-positives AWS Canary tokens)
// and "mock.*server" (false-positives staging environments).
var signatures = []signature{
	{
		name: "Cowrie-SSH",
		re:   regexp.MustCompile(`SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2`),
	},
	{
		name: "Cowrie",
		re:   regexp.MustCompile(`(?i)\b(cowrie|kippo)\b`),
	},
	{
		name: "Dionaea",
		re:   regexp.MustCompile(`(?i)\bdionaea\b`),
	},
	{
		name: "Glastopf",
		re:   regexp.MustCompile(`(?i)\bglastopf\b`),
	},
	{
		name: "Conpot",
		re:   regexp.MustCompile(`(?i)\bconpot\b`),
	},
	{
		name: "Elastichoney",
		re:   regexp.MustCompile(`(?i)\belastichoney\b`),
	},
	{
		name: "Honeyd",
		re:   regexp.MustCompile(`(?i)\b(honeyd|honeynet)\b`),
	},
	{
		name: "CVE-Bait",
		re:   regexp.MustCompile(`CVE-\d{4}-\d{4,7}-CONFIRMED`),
	},
}

// normalizeHost strips scheme and port to produce a canonical, lowercase host key.
// "https://Example.com:443/path?x=1#frag" → "example.com"
// "example.com:8080"                      → "example.com"
// "[::1]:8080"                            → "[::1]"   (bracketed IPv6)
// "2001:db8::1"                           → "2001:db8::1"  (raw IPv6 — unchanged)
func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	// Strip scheme.
	if idx := indexAfterScheme(input); idx >= 0 {
		input = input[idx:]
	}
	// Strip query/fragment tails first so they don't affect keying.
	if qIdx := indexOf(input, '?'); qIdx >= 0 {
		input = input[:qIdx]
	}
	if fIdx := indexOf(input, '#'); fIdx >= 0 {
		input = input[:fIdx]
	}
	// Strip path.
	if idx := indexOf(input, '/'); idx >= 0 {
		input = input[:idx]
	}
	// Strip port — but only when safe to do so.
	if len(input) > 0 && input[0] == '[' {
		// Bracketed IPv6: "[::1]:8080" → keep up to and including ']'.
		if close := indexOf(input, ']'); close >= 0 {
			input = input[:close+1]
		}
	} else if countByte(input, ':') == 1 {
		// Plain "host:port" with exactly one colon — strip the port.
		if idx := indexOf(input, ':'); idx >= 0 {
			input = input[:idx]
		}
	}
	// Raw IPv6 (multiple colons, no brackets) — leave as-is, but lowercase.
	return strings.ToLower(input)
}

// countByte returns the number of occurrences of b in s.
func countByte(s string, b byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			n++
		}
	}
	return n
}

func indexAfterScheme(s string) int {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == ':' && s[i+1] == '/' && s[i+2] == '/' {
			return i + 3
		}
	}
	return -1
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
