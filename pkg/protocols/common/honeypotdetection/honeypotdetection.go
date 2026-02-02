// Package honeypotdetection provides functionality to detect honeypot hosts during security scans.
// A honeypot is a decoy system designed to attract attackers and generate false positives.
// This package identifies hosts that match an abnormally high percentage of templates,
// which is a strong indicator of honeypot behavior.
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
// The default value of 50% means a host matching more than half of all templates is suspicious.
const DefaultThreshold = 50

// MinTemplatesForDetection is the minimum number of templates that must be executed
// against a host before honeypot detection is triggered. This prevents false positives
// when only a few templates have been run against a host.
const MinTemplatesForDetection = 10

// Cache tracks template matches per host for honeypot detection.
// A host that matches an unusually high percentage of templates may be a honeypot
// designed to generate false positives. The cache is safe for concurrent access.
type Cache struct {
	// threshold is the percentage of template matches above which a host is flagged
	threshold int
	// verbose enables detailed logging of honeypot detection events
	verbose bool
	// hostMatches maps normalized host strings to their match statistics
	hostMatches map[string]*hostStats
	// mu protects concurrent access to hostMatches and warnedHosts
	mu sync.RWMutex
	// warnedHosts tracks which hosts we've already warned about to avoid duplicate warnings
	warnedHosts map[string]bool
	// totalScanned is the total number of templates being run in this scan session
	totalScanned int
}

// hostStats tracks match statistics for a single host.
// It maintains counts of matches and scans, along with a set of matched template IDs
// to prevent counting duplicate matches for the same template.
type hostStats struct {
	// matches is the number of unique template matches for this host
	matches int
	// templatesScanned is the number of templates scanned against this host
	templatesScanned int
	// matchedTemplates is a set of template IDs that have matched this host
	matchedTemplates map[string]bool
	// flagged indicates whether this host has been flagged as a potential honeypot
	flagged bool
	// mu protects concurrent access to this host's statistics
	mu sync.Mutex
}

// CacheInterface defines the interface for honeypot detection cache implementations.
// This interface allows for easy mocking in tests and potential alternative implementations.
type CacheInterface interface {
	// SetVerbose enables or disables verbose logging
	SetVerbose(verbose bool)
	// Close cleans up resources and logs final statistics
	Close()
	// SetTotalTemplates sets the total number of templates in the scan
	SetTotalTemplates(count int)
	// RecordMatch records a template match for honeypot tracking
	RecordMatch(host, templateID, urlStr string)
	// IsHoneypot checks if a host has been flagged as a honeypot
	IsHoneypot(host string) bool
	// GetStats returns match statistics for a host
	GetStats(host string) (matches, total int, ratio float64)
	// GetAllSuspectedHoneypots returns information about all flagged hosts
	GetAllSuspectedHoneypots() []HoneypotInfo
}

// HoneypotInfo contains information about a detected honeypot host.
// It provides details about the match rate that triggered the detection.
type HoneypotInfo struct {
	// Host is the normalized host identifier (hostname:port format)
	Host string
	// Matches is the number of templates that matched this host
	Matches int
	// TotalScans is the total number of templates scanned against this host
	TotalScans int
	// Ratio is the percentage of templates that matched (Matches/TotalScans * 100)
	Ratio float64
}

// New creates a new honeypot detection cache with the specified threshold.
// If threshold is <= 0, DefaultThreshold (50%) is used.
// The threshold represents the percentage of template matches above which
// a host will be flagged as a potential honeypot.
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

// SetVerbose enables or disables verbose logging for the cache.
// When enabled, additional debug information may be logged during detection.
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// SetTotalTemplates sets the total number of templates being run in this scan.
// This value is used as the denominator when calculating match percentages
// if per-host scan counts are not available.
func (c *Cache) SetTotalTemplates(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalScanned = count
}

// RecordMatch records a template match for a host and checks for honeypot behavior.
// The host parameter can be a URL, host:port, or bare hostname - it will be normalized.
// The templateID is the unique identifier of the matched template.
// The urlStr parameter is used as a fallback if host is empty.
// Duplicate matches for the same template ID are ignored.
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

// RecordScan records that a template was scanned against a host, regardless of whether it matched.
// This is used to track the denominator for per-host match percentage calculations.
// The host parameter will be normalized before recording.
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

// checkAndWarn checks if a host exceeds the honeypot threshold and emits a warning if necessary.
// It uses a double-check pattern under write lock to prevent duplicate warnings under concurrency.
// This function must NOT be called while holding stats.mu to avoid deadlock.
//
// Parameters:
//   - host: the normalized host identifier
//   - matches: current number of template matches for this host
//   - templatesScanned: number of templates scanned against this host (0 if not tracked)
//   - alreadyFlagged: whether the host was already flagged when the caller checked
func (c *Cache) checkAndWarn(host string, matches, templatesScanned int, alreadyFlagged bool) {
	// Early exit if already flagged (fast path without lock)
	if alreadyFlagged {
		return
	}

	c.mu.RLock()
	totalTemplates := c.totalScanned
	alreadyWarned := c.warnedHosts[host]
	c.mu.RUnlock()

	if alreadyWarned {
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
		// Double-check under write lock to prevent duplicate warnings under concurrency
		c.mu.Lock()
		// Re-check if another goroutine already warned about this host
		if c.warnedHosts[host] {
			c.mu.Unlock()
			return
		}
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

// IsHoneypot returns true if the host has been flagged as a potential honeypot.
// The host parameter will be normalized before checking.
// Returns false if the host is not found or has not been flagged.
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

// GetStats returns the match statistics for a host.
// Returns the number of matches, the total templates scanned (or total session templates),
// and the match ratio as a percentage.
// The host parameter will be normalized before lookup.
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

// GetAllSuspectedHoneypots returns information about all hosts flagged as potential honeypots.
// The returned slice contains HoneypotInfo structs with details about each flagged host.
// Returns an empty slice if no honeypots have been detected.
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

// Close cleans up the cache and logs final honeypot detection statistics.
// It outputs a summary of all detected honeypots and their match rates,
// then resets the internal state. This should be called when the scan completes.
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

// normalizeHost extracts and normalizes the host from various input formats.
// It handles URLs (http://example.com), host:port (example.com:80), and bare hostnames.
// For URLs with standard schemes (http/https), default ports are added for consistency.
// IPv6 addresses are handled correctly, including bracketed notation.
// Returns an empty string if the input cannot be normalized.
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
