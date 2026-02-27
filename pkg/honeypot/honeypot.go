package honeypot

import (
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// Detector tracks unique template matches per host and flags hosts
// that exceed a configurable threshold as likely honeypots. Honeypots
// on platforms like Shodan often return responses that match many
// unrelated nuclei templates to confuse scanners.
//
// The detector is safe for concurrent use.
type Detector struct {
	mu        sync.Mutex
	threshold int
	suppress  bool

	// hostMatches maps normalized host -> set of unique template IDs matched
	hostMatches map[string]map[string]struct{}
	// flagged tracks hosts that have crossed the threshold
	flagged map[string]struct{}
	// warned tracks hosts for which we already printed a warning
	warned map[string]struct{}
}

// New creates a new honeypot Detector with the given threshold. If threshold
// is 0 or negative, the detector is effectively disabled (IsEnabled returns false).
// When suppress is true, results from flagged honeypot hosts will be suppressed.
func New(threshold int, suppress bool) *Detector {
	return &Detector{
		threshold:   threshold,
		suppress:    suppress,
		hostMatches: make(map[string]map[string]struct{}),
		flagged:     make(map[string]struct{}),
		warned:      make(map[string]struct{}),
	}
}

// IsEnabled returns true if the detector is active (threshold > 0).
func (d *Detector) IsEnabled() bool {
	return d.threshold > 0
}

// RecordMatch registers a template match for the given host. It returns
// true if the host was just flagged as a honeypot (crossed threshold),
// false otherwise. This method is thread-safe.
func (d *Detector) RecordMatch(host, templateID string) bool {
	if !d.IsEnabled() {
		return false
	}

	normalized := NormalizeHost(host)
	if normalized == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// If already flagged, no need to track further
	if _, ok := d.flagged[normalized]; ok {
		return false
	}

	templates, exists := d.hostMatches[normalized]
	if !exists {
		templates = make(map[string]struct{})
		d.hostMatches[normalized] = templates
	}
	templates[templateID] = struct{}{}

	if len(templates) >= d.threshold {
		d.flagged[normalized] = struct{}{}
		// Free the template set since we no longer need it after flagging
		delete(d.hostMatches, normalized)
		return true
	}
	return false
}

// IsFlagged returns true if the given host has been identified as a
// likely honeypot. This method is thread-safe.
func (d *Detector) IsFlagged(host string) bool {
	if !d.IsEnabled() {
		return false
	}

	normalized := NormalizeHost(host)
	d.mu.Lock()
	defer d.mu.Unlock()

	_, ok := d.flagged[normalized]
	return ok
}

// ShouldSuppress returns true if results for this host should be suppressed.
// A host is suppressed only if it has been flagged AND the suppress option is enabled.
func (d *Detector) ShouldSuppress(host string) bool {
	if !d.IsEnabled() || !d.suppress {
		return false
	}
	return d.IsFlagged(host)
}

// WarnOnce prints a honeypot warning for the given host, but only the first
// time it is called for that host. Returns true if a warning was emitted.
func (d *Detector) WarnOnce(host string) bool {
	if !d.IsEnabled() {
		return false
	}

	normalized := NormalizeHost(host)
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.warned[normalized]; ok {
		return false
	}
	d.warned[normalized] = struct{}{}

	action := "results may be unreliable"
	if d.suppress {
		action = "subsequent results will be suppressed"
	}
	gologger.Warning().Msgf(
		"[honeypot] %s matched %d+ unique templates (likely honeypot, %s)",
		host, d.threshold, action,
	)
	return true
}

// FlaggedHosts returns a list of all hosts that have been identified as
// likely honeypots. This method is thread-safe.
func (d *Detector) FlaggedHosts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	hosts := make([]string, 0, len(d.flagged))
	for host := range d.flagged {
		hosts = append(hosts, host)
	}
	return hosts
}

// MatchCount returns the number of unique template IDs that have matched
// for the given host. For flagged hosts the exact count is not tracked
// (returns the threshold). This method is thread-safe.
func (d *Detector) MatchCount(host string) int {
	if !d.IsEnabled() {
		return 0
	}

	normalized := NormalizeHost(host)
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.flagged[normalized]; ok {
		return d.threshold
	}
	if templates, ok := d.hostMatches[normalized]; ok {
		return len(templates)
	}
	return 0
}

// PrintSummary outputs a summary of detected honeypot hosts at the end
// of the scan (if any were detected).
func (d *Detector) PrintSummary() {
	if !d.IsEnabled() {
		return
	}
	hosts := d.FlaggedHosts()
	if len(hosts) == 0 {
		return
	}
	gologger.Info().Msgf("[honeypot] Detected %d likely honeypot host(s):", len(hosts))
	for _, host := range hosts {
		gologger.Info().Msgf("  - %s", host)
	}
}

// NormalizeHost extracts a canonical host identifier from a URL, host:port,
// or bare hostname/IP. It strips the scheme, port, path, and query string.
// For IPv6 addresses, brackets are removed.
func NormalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// If it looks like a URL (has scheme), parse it
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}

	// Try host:port format
	// Handle IPv6 with brackets: [::1]:8080
	if strings.HasPrefix(raw, "[") {
		// IPv6 with brackets
		if idx := strings.LastIndex(raw, "]"); idx != -1 {
			return strings.ToLower(raw[1:idx])
		}
	}

	// Regular host:port
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		// Make sure it's not just an IPv6 address without brackets
		if strings.Count(raw, ":") == 1 {
			return strings.ToLower(raw[:idx])
		}
	}

	return strings.ToLower(raw)
}
