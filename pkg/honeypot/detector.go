package honeypot

import (
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// Detector tracks unique template match counts per host to identify
// hosts that match an abnormally high number of templates — a strong
// indicator of a honeypot that returns canned responses designed to
// trigger many nuclei matchers.
type Detector struct {
	mu      sync.Mutex
	hosts   map[string]*hostEntry
	max     int  // 0 means disabled
	total   int  // total number of templates loaded (for percentage mode)
	minPct  int  // minimum percentage of templates to trigger (default 50)
	suppress bool

	// track how many hosts have been flagged
	flagged atomic.Int64
}

type hostEntry struct {
	templates map[string]struct{}
	warned    bool
}

// New creates a new honeypot detector.
// max: absolute threshold for unique template matches per host (0 = disabled)
// total: total template count (0 = skip percentage check)
// suppress: if true, results from flagged hosts are dropped
func New(max, total, minPct int, suppress bool) *Detector {
	return &Detector{
		hosts:    make(map[string]*hostEntry),
		max:      max,
		total:    total,
		minPct:   minPct,
		suppress: suppress,
	}
}

// RecordMatch records that templateID matched on host. Returns true if
// the host has been flagged as a honeypot.
func (d *Detector) RecordMatch(host, templateID string) bool {
	if d.max <= 0 && d.total <= 0 {
		return false
	}

	key := normalizeHost(host)

	d.mu.Lock()
	defer d.mu.Unlock()

	entry, ok := d.hosts[key]
	if !ok {
		entry = &hostEntry{templates: make(map[string]struct{})}
		d.hosts[key] = entry
	}
	if entry.warned {
		return true
	}

	entry.templates[templateID] = struct{}{}
	count := len(entry.templates)

	// Check absolute threshold
	if d.max > 0 && count >= d.max {
		entry.warned = true
		d.flagged.Add(1)
		return true
	}

	// Check percentage threshold
	if d.total > 0 && d.minPct > 0 {
		pct := count * 100 / d.total
		if pct >= d.minPct {
			entry.warned = true
			d.flagged.Add(1)
			return true
		}
	}

	return false
}

// IsFlagged returns whether a host has already been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	if d.max <= 0 && d.total <= 0 {
		return false
	}

	key := normalizeHost(host)

	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, ok := d.hosts[key]; ok && entry.warned {
		return true
	}
	return false
}

// FlaggedCount returns the number of hosts flagged as honeypots.
func (d *Detector) FlaggedCount() int64 {
	return d.flagged.Load()
}

// Enabled returns whether honeypot detection is active.
func (d *Detector) Enabled() bool {
	return d.max > 0 || d.total > 0
}

// Suppress returns whether results from flagged hosts should be suppressed.
func (d *Detector) Suppress() bool {
	return d.suppress
}

// normalizeHost reduces a host URL to a canonical key for grouping.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	// Remove scheme
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}

	// Remove path, query, fragment
	for i, c := range host {
		if c == '/' || c == '?' || c == '#' {
			host = host[:i]
			break
		}
	}

	// Handle bracketed IPv6 [::1]:port
	if strings.HasPrefix(host, "[") {
		if close := strings.Index(host, "]"); close != -1 {
			host = host[:close+1]
		}
		return host
	}

	// Remove port for IPv4/hostname
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	return strings.ToLower(host)
}

// KnownHoneypotSignatures returns common honeypot software signatures
// found in HTTP response bodies/headers.
var KnownHoneypotSignatures = []string{
	"cowrie",
	"dionaea",
	"glastopf",
	"conpot",
	"kippo",
	"wordpot",
	"elasticpot",
	"honeytrap",
	"amun",
	"snort",
	"p0f",
	"t-pot",
	"honeypot",
}

// CheckSignature checks if a response body contains known honeypot signatures.
func CheckSignature(body string) (string, bool) {
	lower := strings.ToLower(body)
	for _, sig := range KnownHoneypotSignatures {
		if strings.Contains(lower, sig) {
			return sig, true
		}
	}
	return "", false
}

// HostURL extracts just the host:port portion for grouping.
func HostURL(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		h := u.Hostname()
		if u.Port() != "" {
			return h + ":" + u.Port()
		}
		return h
	}
	return normalizeHost(rawurl)
}
