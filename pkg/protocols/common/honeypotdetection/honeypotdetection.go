package honeypotdetection

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// DefaultThreshold is the default percentage threshold for honeypot detection.
// If a host matches more than this percentage of templates, it's flagged as a potential honeypot.
const DefaultThreshold = 50

// MinTemplatesForDetection is the minimum number of templates that must be executed
// against a host before honeypot detection is triggered.
const MinTemplatesForDetection = 10

// Cache tracks template matches per host for honeypot detection.
// A host that matches an unusually high percentage of templates may be a honeypot
// designed to generate false positives.
type Cache struct {
	threshold    int
	verbose      bool
	hostMatches  map[string]*hostStats
	mu           sync.RWMutex
	warnedHosts  map[string]bool // tracks which hosts we've already warned about
	totalScanned int             // total templates scanned in this session
}

// hostStats tracks match statistics for a single host.
type hostStats struct {
	matches          int                    // number of template matches
	templatesScanned int                    // number of templates scanned against this host
	matchedTemplates map[string]bool        // set of matched template IDs
	flagged          bool                   // whether this host has been flagged as honeypot
	mu               sync.Mutex
}

// CacheInterface defines the signature of the honeypot detection cache
type CacheInterface interface {
	SetVerbose(verbose bool)
	Close()
	SetTotalTemplates(count int)
	RecordMatch(host, templateID, urlStr string)
	IsHoneypot(host string) bool
	GetStats(host string) (matches, total int, ratio float64)
	GetAllSuspectedHoneypots() []HoneypotInfo
}

// HoneypotInfo contains information about a detected honeypot
type HoneypotInfo struct {
	Host       string
	Matches    int
	TotalScans int
	Ratio      float64
}

// New creates a new honeypot detection cache
func New(threshold int) *Cache {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Cache{
		threshold:   threshold,
		hostMatches: make(map[string]*hostStats),
		warnedHosts: make(map[string]bool),
	}
}

// SetVerbose enables verbose logging
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// SetTotalTemplates sets the total number of templates being run in this scan
func (c *Cache) SetTotalTemplates(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalScanned = count
}

// RecordMatch records a template match for a host
// host can be a URL, host:port, or hostname
// templateID is the ID of the matched template
func (c *Cache) RecordMatch(host, templateID, urlStr string) {
	normalizedHost := c.normalizeHost(host)
	if normalizedHost == "" {
		// Try to extract from URL
		normalizedHost = c.normalizeHost(urlStr)
	}
	if normalizedHost == "" {
		return
	}

	c.mu.Lock()
	stats, exists := c.hostMatches[normalizedHost]
	if !exists {
		stats = &hostStats{
			matchedTemplates: make(map[string]bool),
		}
		c.hostMatches[normalizedHost] = stats
	}
	c.mu.Unlock()

	stats.mu.Lock()
	// Record the match if we haven't seen this template for this host
	if templateID != "" && !stats.matchedTemplates[templateID] {
		stats.matchedTemplates[templateID] = true
		stats.matches++
	}
	// Copy values needed for checkAndWarn while holding stats.mu
	matches := stats.matches
	templatesScanned := stats.templatesScanned
	flagged := stats.flagged
	stats.mu.Unlock()

	// Check if this host should be flagged (without holding stats.mu to avoid deadlock)
	c.checkAndWarn(normalizedHost, matches, templatesScanned, flagged)
}

// RecordScan records that a template was scanned against a host (regardless of match)
func (c *Cache) RecordScan(host string) {
	host = c.normalizeHost(host)
	if host == "" {
		return
	}

	c.mu.Lock()
	stats, exists := c.hostMatches[host]
	if !exists {
		stats = &hostStats{
			matchedTemplates: make(map[string]bool),
		}
		c.hostMatches[host] = stats
	}
	c.mu.Unlock()

	stats.mu.Lock()
	stats.templatesScanned++
	stats.mu.Unlock()
}

// checkAndWarn checks if a host exceeds the honeypot threshold and warns if necessary
// Note: This function must NOT be called while holding stats.mu to avoid deadlock
func (c *Cache) checkAndWarn(host string, matches, templatesScanned int, alreadyFlagged bool) {
	c.mu.RLock()
	totalTemplates := c.totalScanned
	alreadyWarned := c.warnedHosts[host]
	c.mu.RUnlock()

	if alreadyWarned || alreadyFlagged {
		return
	}

	// Use templatesScanned if available, otherwise fall back to totalScanned
	denominator := templatesScanned
	if denominator == 0 {
		denominator = totalTemplates
	}
	if denominator < MinTemplatesForDetection {
		return
	}

	ratio := float64(matches) / float64(denominator) * 100

	if ratio >= float64(c.threshold) {
		// Mark as warned and flagged
		c.mu.Lock()
		c.warnedHosts[host] = true
		stats := c.hostMatches[host]
		c.mu.Unlock()

		if stats != nil {
			stats.mu.Lock()
			stats.flagged = true
			stats.mu.Unlock()
		}

		gologger.Warning().Msgf("[HONEYPOT] Potential honeypot detected: %s matched %.1f%% of templates (%d/%d). Results may be false positives.",
			host, ratio, matches, denominator)
	}
}

// IsHoneypot returns true if the host has been flagged as a potential honeypot
func (c *Cache) IsHoneypot(host string) bool {
	host = c.normalizeHost(host)
	if host == "" {
		return false
	}

	c.mu.RLock()
	stats, exists := c.hostMatches[host]
	c.mu.RUnlock()

	if !exists {
		return false
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()
	return stats.flagged
}

// GetStats returns the match statistics for a host
func (c *Cache) GetStats(host string) (matches, total int, ratio float64) {
	host = c.normalizeHost(host)
	if host == "" {
		return 0, 0, 0
	}

	c.mu.RLock()
	stats, exists := c.hostMatches[host]
	totalTemplates := c.totalScanned
	c.mu.RUnlock()

	if !exists {
		return 0, totalTemplates, 0
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	denominator := stats.templatesScanned
	if denominator == 0 {
		denominator = totalTemplates
	}

	if denominator > 0 {
		ratio = float64(stats.matches) / float64(denominator) * 100
	}
	return stats.matches, denominator, ratio
}

// GetAllSuspectedHoneypots returns information about all hosts flagged as potential honeypots
func (c *Cache) GetAllSuspectedHoneypots() []HoneypotInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var honeypots []HoneypotInfo
	for host, stats := range c.hostMatches {
		stats.mu.Lock()
		if stats.flagged {
			denominator := stats.templatesScanned
			if denominator == 0 {
				denominator = c.totalScanned
			}
			ratio := 0.0
			if denominator > 0 {
				ratio = float64(stats.matches) / float64(denominator) * 100
			}
			honeypots = append(honeypots, HoneypotInfo{
				Host:       host,
				Matches:    stats.matches,
				TotalScans: denominator,
				Ratio:      ratio,
			})
		}
		stats.mu.Unlock()
	}
	return honeypots
}

// Close cleans up and logs final honeypot detection statistics
func (c *Cache) Close() {
	honeypots := c.GetAllSuspectedHoneypots()
	if len(honeypots) > 0 {
		gologger.Warning().Msgf("[HONEYPOT] Summary: %d potential honeypot(s) detected during scan:", len(honeypots))
		for _, hp := range honeypots {
			gologger.Warning().Msgf("  - %s: %.1f%% match rate (%d/%d templates)", hp.Host, hp.Ratio, hp.Matches, hp.TotalScans)
		}
		gologger.Warning().Msg("[HONEYPOT] Results from these hosts may be intentional false positives. Consider excluding them from your analysis.")
	}

	c.mu.Lock()
	c.hostMatches = make(map[string]*hostStats)
	c.warnedHosts = make(map[string]bool)
	c.mu.Unlock()
}

// normalizeHost extracts and normalizes the host from various input formats
func (c *Cache) normalizeHost(value string) string {
	if value == "" {
		return ""
	}

	// Try parsing as URL first
	if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err == nil && u.Host != "" {
			host := u.Hostname()
			port := u.Port()
			if port != "" {
				return net.JoinHostPort(host, port)
			}
			// Add default ports for consistency
			switch u.Scheme {
			case "https":
				return net.JoinHostPort(host, "443")
			case "http":
				return net.JoinHostPort(host, "80")
			default:
				return host
			}
		}
	}

	// Try parsing as host:port format
	// Use net.SplitHostPort first, which correctly handles IPv6 addresses like [::1]:8080
	if host, port, err := net.SplitHostPort(value); err == nil {
		return net.JoinHostPort(host, port)
	}

	// If SplitHostPort failed, it could be:
	// - A plain hostname (example.com)
	// - An IPv6 address without port ([::1] or ::1)
	// - A hostname without port

	// Handle bracketed IPv6 without port (e.g., [::1])
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return value[1 : len(value)-1] // Remove brackets, return raw IPv6
	}

	// Return as-is (hostname or bare IPv6 address)
	return value
}
