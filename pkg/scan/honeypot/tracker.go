package honeypot

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	// DefaultThreshold is the default number of unique template matches
	// per host before flagging it as a potential honeypot.
	DefaultThreshold = 100

	// DefaultMatchPercentage is the default percentage of templates
	// that must match before a host is considered a honeypot.
	// This is used as a secondary check when total templates count is known.
	DefaultMatchPercentage = 75.0

	// DefaultMaxHosts is the maximum number of unique hosts tracked
	// to prevent unbounded memory growth.
	DefaultMaxHosts = 100000
)

// hostStats tracks match statistics for a single host.
type hostStats struct {
	// templateIDs stores unique template IDs that matched this host.
	templateIDs map[string]struct{}
	// flagged indicates whether this host has been flagged as a honeypot.
	flagged bool
}

// Tracker monitors per-host template match counts to detect
// potential honeypots. Honeypots typically respond positively
// to many different vulnerability checks, producing an abnormally
// high match rate across diverse template categories.
type Tracker struct {
	mu sync.RWMutex

	// hosts maps normalized host identifiers to their match statistics.
	hosts map[string]*hostStats

	// threshold is the absolute number of unique template matches
	// that triggers honeypot detection for a host.
	threshold int

	// totalTemplates is the total number of templates being executed.
	// When set, allows percentage-based detection as well.
	totalTemplates int

	// maxHosts is the maximum number of hosts to track to prevent
	// unbounded memory growth from crafted target lists.
	maxHosts int

	// logger is used for warning/info messages.
	logger *gologger.Logger
}

// NewTracker creates a new honeypot detection tracker.
func NewTracker(threshold int, logger *gologger.Logger) *Tracker {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Tracker{
		hosts:     make(map[string]*hostStats),
		threshold: threshold,
		maxHosts:  DefaultMaxHosts,
		logger:    logger,
	}
}

// SetTotalTemplates sets the total number of templates for percentage-based detection.
func (t *Tracker) SetTotalTemplates(count int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalTemplates = count
}

// RecordMatch records a template match for a given host and template ID.
// Returns true if the host is now flagged as a potential honeypot.
func (t *Tracker) RecordMatch(host, templateID string) bool {
	normalizedHost := normalizeHost(host)
	if normalizedHost == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	stats, ok := t.hosts[normalizedHost]
	if !ok {
		// Prevent unbounded memory growth from very large target lists.
		if len(t.hosts) >= t.maxHosts {
			return false
		}
		stats = &hostStats{
			templateIDs: make(map[string]struct{}),
		}
		t.hosts[normalizedHost] = stats
	}

	// Track unique template IDs only.
	stats.templateIDs[templateID] = struct{}{}
	matchCount := len(stats.templateIDs)

	// Check if the host should be flagged.
	if !stats.flagged && t.shouldFlag(matchCount) {
		stats.flagged = true
		if t.logger != nil {
			t.logger.Warning().Msgf(
				"[honeypot] Host %s matched %d unique templates (threshold: %d) - potential honeypot detected",
				normalizedHost, matchCount, t.threshold,
			)
		}
		return true
	}

	return false
}

// IsHoneypot checks if a host has been flagged as a potential honeypot.
func (t *Tracker) IsHoneypot(host string) bool {
	normalizedHost := normalizeHost(host)
	if normalizedHost == "" {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if stats, ok := t.hosts[normalizedHost]; ok {
		return stats.flagged
	}
	return false
}

// GetMatchCount returns the number of unique template matches for a host.
func (t *Tracker) GetMatchCount(host string) int {
	normalizedHost := normalizeHost(host)
	if normalizedHost == "" {
		return 0
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if stats, ok := t.hosts[normalizedHost]; ok {
		return len(stats.templateIDs)
	}
	return 0
}

// GetFlaggedHosts returns a list of all hosts flagged as potential honeypots
// along with their match counts.
func (t *Tracker) GetFlaggedHosts() []FlaggedHost {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var flagged []FlaggedHost
	for host, stats := range t.hosts {
		if stats.flagged {
			flagged = append(flagged, FlaggedHost{
				Host:       host,
				MatchCount: len(stats.templateIDs),
			})
		}
	}

	// Sort for deterministic output: by match count descending,
	// then by host name ascending to break ties.
	sort.Slice(flagged, func(i, j int) bool {
		if flagged[i].MatchCount == flagged[j].MatchCount {
			return flagged[i].Host < flagged[j].Host
		}
		return flagged[i].MatchCount > flagged[j].MatchCount
	})
	return flagged
}

// Summary returns a human-readable summary of honeypot detection results.
func (t *Tracker) Summary() string {
	flagged := t.GetFlaggedHosts()
	if len(flagged) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[honeypot] %d potential honeypot(s) detected:\n", len(flagged)))
	for _, h := range flagged {
		sb.WriteString(fmt.Sprintf("  - %s (%d unique template matches)\n", h.Host, h.MatchCount))
	}
	return sb.String()
}

// FlaggedHost represents a host that has been flagged as a potential honeypot.
type FlaggedHost struct {
	Host       string `json:"host"`
	MatchCount int    `json:"match_count"`
}

// shouldFlag determines if a host should be flagged based on match count.
// Called with lock held.
func (t *Tracker) shouldFlag(matchCount int) bool {
	// Primary check: absolute threshold.
	if matchCount >= t.threshold {
		return true
	}

	// Secondary check: percentage of total templates (if known).
	if t.totalTemplates > 0 {
		percentage := (float64(matchCount) / float64(t.totalTemplates)) * 100
		if percentage >= DefaultMatchPercentage && matchCount >= 10 {
			// Only trigger percentage-based detection if at least 10 templates matched.
			// This avoids false positives when scanning with very few templates.
			return true
		}
	}

	return false
}

// normalizeHost extracts a consistent host identifier from various input formats.
// It strips protocol, path, and normalizes the host:port combination.
func normalizeHost(input string) string {
	if input == "" {
		return ""
	}

	// Try to parse as URL first.
	parsed, err := urlutil.Parse(input)
	if err == nil && parsed.Host != "" {
		host := parsed.Host
		// Strip default ports safely using net.SplitHostPort to avoid
		// corrupting IPv6 addresses like 2001:db8::80.
		host = stripDefaultPort(host)
		return strings.ToLower(host)
	}

	// Fall back to treating it as a plain host.
	input = strings.ToLower(strings.TrimSpace(input))
	input = stripDefaultPort(input)
	return input
}

// stripDefaultPort removes :80 and :443 from host:port strings only when
// they are actual port suffixes (not part of an IPv6 address).
// It also unwraps bare bracketed IPv6 literals (e.g. "[::1]" → "::1")
// so that http://[::1]/ and http://[::1]:80/ normalize to the same key.
func stripDefaultPort(hostport string) string {
	// Handle bare bracketed IPv6 without port (e.g. "[2001:db8::1]").
	// net.SplitHostPort won't parse these, but they should normalize
	// to the same form as "[2001:db8::1]:80" → "2001:db8::1".
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport[1 : len(hostport)-1]
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port present or invalid format; return as-is.
		return hostport
	}
	if port == "80" || port == "443" {
		return host
	}
	return hostport
}
