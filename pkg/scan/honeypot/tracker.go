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

// flagReason describes why a host was flagged as a potential honeypot.
type flagReason int

const (
	notFlagged        flagReason = iota
	flagAbsolute                         // absolute threshold exceeded
	flagPercentage                       // percentage-of-templates threshold exceeded
)

// String returns a human-readable description of the flag reason.
func (r flagReason) String() string {
	switch r {
	case flagAbsolute:
		return "absolute threshold"
	case flagPercentage:
		return "percentage-of-templates threshold"
	default:
		return ""
	}
}

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

	// droppedHosts counts how many record attempts were excluded because
	// the maxHosts limit was reached. Note: this counts all excluded
	// attempts, not unique hosts, since excluded hosts are not tracked.
	droppedHosts int

	// maxHostsWarned ensures the maxHosts warning is emitted only once.
	maxHostsWarned bool

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
			t.droppedHosts++
			if !t.maxHostsWarned {
				t.maxHostsWarned = true
				if t.logger != nil {
					t.logger.Warning().Msgf(
						"[honeypot] Maximum tracked hosts limit reached (%d); new hosts will be excluded from honeypot detection",
						t.maxHosts,
					)
				}
			}
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
	if reason := t.shouldFlag(matchCount); !stats.flagged && reason != notFlagged {
		stats.flagged = true
		if t.logger != nil {
			var detail string
			switch reason {
			case flagAbsolute:
				detail = fmt.Sprintf("threshold: %d", t.threshold)
			case flagPercentage:
				pct := (float64(matchCount) / float64(t.totalTemplates)) * 100
				detail = fmt.Sprintf("%.0f%% of %d templates", pct, t.totalTemplates)
			}
			t.logger.Warning().Msgf(
				"[honeypot] Host %s matched %d unique templates (%s) - potential honeypot detected",
				normalizedHost, matchCount, detail,
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

// DroppedHosts returns the number of record attempts that were excluded from
// honeypot tracking because the maxHosts limit was reached. This counts all
// excluded attempts, not unique hosts, since excluded hosts are not tracked.
func (t *Tracker) DroppedHosts() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.droppedHosts
}

// Summary returns a human-readable summary of honeypot detection results.
func (t *Tracker) Summary() string {
	flagged := t.GetFlaggedHosts()
	dropped := t.DroppedHosts()

	if len(flagged) == 0 && dropped == 0 {
		return ""
	}

	var sb strings.Builder
	if len(flagged) > 0 {
		sb.WriteString(fmt.Sprintf("[honeypot] %d potential honeypot(s) detected:\n", len(flagged)))
		for _, h := range flagged {
			sb.WriteString(fmt.Sprintf("  - %s (%d unique template matches)\n", h.Host, h.MatchCount))
		}
	}
	if dropped > 0 {
		sb.WriteString(fmt.Sprintf("[honeypot] %d host(s) excluded from tracking (max hosts limit: %d)\n", dropped, t.maxHosts))
	}
	return sb.String()
}

// FlaggedHost represents a host that has been flagged as a potential honeypot.
type FlaggedHost struct {
	Host       string `json:"host"`
	MatchCount int    `json:"match_count"`
}

// shouldFlag determines if a host should be flagged based on match count
// and returns the reason for flagging (or notFlagged if the host should not
// be flagged). Called with lock held.
func (t *Tracker) shouldFlag(matchCount int) flagReason {
	// Primary check: absolute threshold.
	if matchCount >= t.threshold {
		return flagAbsolute
	}

	// Secondary check: percentage of total templates (if known).
	if t.totalTemplates > 0 {
		percentage := (float64(matchCount) / float64(t.totalTemplates)) * 100
		if percentage >= DefaultMatchPercentage && matchCount >= 10 {
			// Only trigger percentage-based detection if at least 10 templates matched.
			// This avoids false positives when scanning with very few templates.
			return flagPercentage
		}
	}

	return notFlagged
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
