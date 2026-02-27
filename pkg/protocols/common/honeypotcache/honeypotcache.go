package honeypotcache

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// CacheInterface defines the signature of the honeypot cache so that
// users of Nuclei as embedded lib may implement their own cache
type CacheInterface interface {
	SetVerbose(verbose bool)
	SetTotalTemplates(total int)
	Close()
	// Check returns true if the host should be skipped (flagged as honeypot)
	Check(ctx *contextargs.Context) bool
	// MarkMatch records a successful template match for the host
	MarkMatch(ctx *contextargs.Context, templateID string)
	// IsHoneypot returns true if the host is flagged as a potential honeypot
	IsHoneypot(ctx *contextargs.Context) bool
	// GetMatchPercentage returns the match percentage for a host
	GetMatchPercentage(ctx *contextargs.Context) float64
	// CheckSignature checks for known honeypot signatures in the response
	CheckSignature(response string) (bool, string)
}

var (
	_ CacheInterface = (*Cache)(nil)
)

// Cache is a cache for honeypot detection. It tracks successful matches
// per host and flags hosts that match an abnormally high number of templates.
type Cache struct {
	Threshold      int // percentage threshold (0-100)
	Suppress       bool
	TotalTemplates int
	verbose        bool
	matchedHosts   gcache.Cache[string, *hostMatches]
	mu             sync.RWMutex
}

type hostMatches struct {
	sync.Once
	matches        map[string]bool // set of matched template IDs
	matchCount     atomic.Int32
	flaggedWarning bool
	mu             sync.Mutex
}

const DefaultMaxHostsCount = 10000

// Known honeypot signature patterns
var honeypotSignatures = []struct {
	name    string
	pattern *regexp.Regexp
}{
	// Specific honeypot products (check first for more specific matches)
	{"Cowrie-SSH", regexp.MustCompile(`SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2`)},
	{"Cowrie", regexp.MustCompile(`(?i)\b(cowrie|kippo)\b`)},
	{"Dionaea", regexp.MustCompile(`(?i)\bdionaea\b`)},
	{"Glastopf", regexp.MustCompile(`(?i)\bglastopf\b`)},
	{"Conpot", regexp.MustCompile(`(?i)\bconpot\b`)},
	{"Elastichoney", regexp.MustCompile(`(?i)\belastichoney\b`)},

	// Generic honeypot indicators
	{"Generic-Honeypot", regexp.MustCompile(`(?i)\b(honeypot|honeyd|honeynet|canary)\b`)},

	// Behavioral patterns
	{"Fake-Service", regexp.MustCompile(`(?i)fake.*service|mock.*server|emulated`)},
	{"All-Ports-Open", regexp.MustCompile(`(?i)all.*ports.*open`)},
}

// New returns a new honeypot detection cache
func New(threshold int, suppress bool, maxHostsCount int) *Cache {
	gc := gcache.New[string, *hostMatches](maxHostsCount).
		ARC().
		LoaderFunc(func(key string) (*hostMatches, error) {
			return &hostMatches{
				matches: make(map[string]bool),
			}, nil
		}).
		Build()

	return &Cache{
		matchedHosts: gc,
		Threshold:    threshold,
		Suppress:     suppress,
	}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// SetTotalTemplates sets the total number of templates being executed
func (c *Cache) SetTotalTemplates(total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.TotalTemplates = total
}

// Close closes the honeypot cache and displays statistics
func (c *Cache) Close() {
	items := c.matchedHosts.GetALL(false)
	for host, matches := range items {
		if matches.matchCount.Load() > 0 {
			percentage := c.calculatePercentage(int(matches.matchCount.Load()))
			if percentage >= float64(c.Threshold) {
				gologger.Info().Label("HoneypotStats").Msgf("Host: %s, Matches: %d (%.1f%%)", host, matches.matchCount.Load(), percentage)
			}
		}
	}
	c.matchedHosts.Purge()
}

// NormalizeCacheValue processes the input value and returns a normalized cache value
func (c *Cache) NormalizeCacheValue(value string) string {
	var normalizedValue = value

	u, err := url.ParseRequestURI(value)
	if err != nil || u.Host == "" {
		if strings.Contains(value, ":") {
			return normalizedValue
		}
		u, err2 := url.ParseRequestURI("https://" + value)
		if err2 != nil {
			return normalizedValue
		}
		normalizedValue = u.Host
	} else {
		port := u.Port()
		if port == "" {
			switch u.Scheme {
			case "https":
				normalizedValue = net.JoinHostPort(u.Host, "443")
			case "http":
				normalizedValue = net.JoinHostPort(u.Host, "80")
			}
		} else {
			normalizedValue = u.Host
		}
	}

	return normalizedValue
}

// GetKeyFromContext returns the key for the cache from the context
func (c *Cache) GetKeyFromContext(ctx *contextargs.Context) string {
	address := ctx.MetaInput.Address()
	return c.NormalizeCacheValue(address)
}

// Check returns true if a host should be skipped as it has been flagged as a honeypot
func (c *Cache) Check(ctx *contextargs.Context) bool {
	if c.Threshold <= 0 || !c.Suppress {
		return false
	}

	finalValue := c.GetKeyFromContext(ctx)
	cache, err := c.matchedHosts.GetIFPresent(finalValue)
	if err != nil {
		return false
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	percentage := c.calculatePercentage(int(cache.matchCount.Load()))
	if percentage >= float64(c.Threshold) {
		cache.Do(func() {
			gologger.Warning().Msgf("[HONEYPOT?] %s matched %.1f%% of templates - flagged as potential honeypot", finalValue, percentage)
		})
		return true
	}

	return false
}

// MarkMatch records a successful template match for a host
func (c *Cache) MarkMatch(ctx *contextargs.Context, templateID string) {
	if c.Threshold <= 0 {
		return
	}

	cacheKey := c.GetKeyFromContext(ctx)
	// Use Get() which triggers LoaderFunc for atomic initialization
	cache, err := c.matchedHosts.Get(cacheKey)
	if err != nil {
		return
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Only count unique template matches
	if !cache.matches[templateID] {
		cache.matches[templateID] = true
		cache.matchCount.Add(1)
	}

	// Check if we should emit a warning
	percentage := c.calculatePercentage(int(cache.matchCount.Load()))
	if percentage >= float64(c.Threshold) && !cache.flaggedWarning {
		cache.flaggedWarning = true
		gologger.Warning().Msgf("[HONEYPOT?] %s matched %.1f%% of templates", cacheKey, percentage)
	}
}

// IsHoneypot returns true if the host is flagged as a potential honeypot
func (c *Cache) IsHoneypot(ctx *contextargs.Context) bool {
	if c.Threshold <= 0 {
		return false
	}

	cacheKey := c.GetKeyFromContext(ctx)
	cache, err := c.matchedHosts.GetIFPresent(cacheKey)
	if err != nil {
		return false
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	percentage := c.calculatePercentage(int(cache.matchCount.Load()))
	return percentage >= float64(c.Threshold)
}

// GetMatchPercentage returns the match percentage for a host
func (c *Cache) GetMatchPercentage(ctx *contextargs.Context) float64 {
	cacheKey := c.GetKeyFromContext(ctx)
	cache, err := c.matchedHosts.GetIFPresent(cacheKey)
	if err != nil {
		return 0
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	return c.calculatePercentage(int(cache.matchCount.Load()))
}

// calculatePercentage calculates the match percentage
func (c *Cache) calculatePercentage(matchCount int) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.TotalTemplates <= 0 {
		return 0
	}
	return (float64(matchCount) / float64(c.TotalTemplates)) * 100
}

// CheckSignature checks for known honeypot signatures in the response
func (c *Cache) CheckSignature(response string) (bool, string) {
	for _, sig := range honeypotSignatures {
		if sig.pattern.MatchString(response) {
			return true, sig.name
		}
	}
	return false, ""
}
