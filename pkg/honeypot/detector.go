package honeypot

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// Detector tracks unique template matches per host to identify potential honeypots.
// Honeypots are hosts that respond positively to an unusually high number of vulnerability
// checks, indicating they are deliberately mirroring scanner signatures to produce false positives.
type Detector struct {
	// threshold is the minimum number of unique template matches to flag a host as a honeypot.
	// A value of 0 means detection is disabled.
	threshold int
	// suppress controls whether results from flagged hosts are suppressed (true) or only warned (false).
	suppress bool
	// matches tracks unique template IDs matched per normalized host.
	// Entries are pruned once a host is flagged to bound memory growth.
	matches map[string]map[string]struct{}
	// flagged tracks hosts that have been flagged as honeypots, storing the match count
	// at the time of flagging. This allows matches to be pruned while preserving counts.
	flagged map[string]int
	// mu protects concurrent access to matches and flagged maps.
	mu sync.RWMutex
}

// New creates a new honeypot Detector with the given threshold and suppression mode.
// A threshold of 0 disables detection entirely.
func New(threshold int, suppress bool) *Detector {
	return &Detector{
		threshold: threshold,
		suppress:  suppress,
		matches:   make(map[string]map[string]struct{}),
		flagged:   make(map[string]int),
	}
}

// Enabled returns true if honeypot detection is active.
func (d *Detector) Enabled() bool {
	return d != nil && d.threshold > 0
}

// Record registers a template match for a host and returns whether the result
// should be suppressed. It returns (isFlagged, shouldSuppress).
//
// isFlagged is true if the host has been identified as a potential honeypot.
// shouldSuppress is true only if isFlagged is true AND suppress mode is enabled.
func (d *Detector) Record(host, templateID string) (isFlagged, shouldSuppress bool) {
	if !d.Enabled() {
		return false, false
	}
	if host == "" || templateID == "" {
		return false, false
	}

	normalizedHost := normalizeHost(host)

	d.mu.Lock()

	// If already flagged, skip counting
	if _, ok := d.flagged[normalizedHost]; ok {
		d.mu.Unlock()
		return true, d.suppress
	}

	templates, ok := d.matches[normalizedHost]
	if !ok {
		templates = make(map[string]struct{})
		d.matches[normalizedHost] = templates
	}
	templates[templateID] = struct{}{}

	if len(templates) >= d.threshold {
		matchCount := len(templates)
		// Store the match count in flagged map and prune the per-template set:
		// once flagged, Record() short-circuits on the flagged check above,
		// so these entries would never be read again. This bounds memory growth
		// for scans with many flagged hosts.
		d.flagged[normalizedHost] = matchCount
		delete(d.matches, normalizedHost)
		d.mu.Unlock()
		// Log outside the lock to avoid stalling concurrent writers
		gologger.Warning().Msgf("[honeypot] %s matched %d unique templates (threshold: %d) — likely honeypot", normalizedHost, matchCount, d.threshold)
		return true, d.suppress
	}

	d.mu.Unlock()
	return false, false
}

// IsFlagged returns whether a host has been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	if !d.Enabled() {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.flagged[normalizeHost(host)]
	return ok
}

// FlaggedHosts returns a list of all hosts flagged as honeypots with their match counts.
func (d *Detector) FlaggedHosts() map[string]int {
	if !d.Enabled() {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]int, len(d.flagged))
	for host, count := range d.flagged {
		result[host] = count
	}
	return result
}

// Summary returns a human-readable summary of flagged hosts, or an empty string if none.
func (d *Detector) Summary() string {
	flagged := d.FlaggedHosts()
	if len(flagged) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[honeypot] %d host(s) flagged as potential honeypot(s):\n", len(flagged)))
	for host, count := range flagged {
		sb.WriteString(fmt.Sprintf("  - %s (%d unique template matches)\n", host, count))
	}
	return sb.String()
}

// normalizeHost extracts a consistent host identifier from various URL/host formats.
// It strips scheme, path, query, fragment, and userinfo, keeping only host:port.
func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it looks like a URL, parse it
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil {
			host := u.Hostname()
			port := u.Port()
			if port != "" {
				// Preserve bracket notation for IPv6 to avoid ambiguity
				if strings.Contains(host, ":") {
					return "[" + host + "]:" + port
				}
				return host + ":" + port
			}
			return host
		}
	}

	// Strip any path component
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	// Strip userinfo if present (user:pass@host)
	if idx := strings.LastIndex(input, "@"); idx != -1 {
		input = input[idx+1:]
	}

	// Preserve IPv6 bracket notation: [::1]:8080 stays as [::1]:8080
	if strings.HasPrefix(input, "[") {
		if closeBracket := strings.Index(input, "]"); closeBracket != -1 {
			host := input[1:closeBracket]
			if closeBracket+1 < len(input) && input[closeBracket+1] == ':' {
				return "[" + host + "]:" + input[closeBracket+2:]
			}
			return "[" + host + "]"
		}
	}

	return input
}
