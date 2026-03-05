package honeypot

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Detector tracks template matches per host and flags hosts that exceed
// a configurable threshold as likely honeypots. Hosts on services like
// Shodan sometimes embed responses that match many nuclei templates in
// order to mislead scanners. When the number of distinct template
// matches for a single host exceeds the threshold, the host is flagged.
//
// The detector is safe for concurrent use.
type Detector struct {
	mu        sync.Mutex
	threshold int
	// matches maps normalized host -> set of matched template IDs
	matches map[string]map[string]struct{}
	// flagged tracks hosts that have been flagged as honeypots
	flagged map[string]bool
}

// New creates a new honeypot Detector with the given threshold.
// A threshold of 0 or negative disables detection.
func New(threshold int) *Detector {
	return &Detector{
		threshold: threshold,
		matches:   make(map[string]map[string]struct{}),
		flagged:   make(map[string]bool),
	}
}

// Enabled returns true if the detector is active (threshold > 0).
func (d *Detector) Enabled() bool {
	return d != nil && d.threshold > 0
}

// Record records a template match for a host and returns true if
// the host has been flagged as a honeypot (either previously or
// as a result of this call). If the detector is disabled, it
// always returns false.
func (d *Detector) Record(host, templateID string) bool {
	if !d.Enabled() {
		return false
	}

	normalized := NormalizeHost(host)
	if normalized == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	templates, ok := d.matches[normalized]
	if !ok {
		templates = make(map[string]struct{})
		d.matches[normalized] = templates
	}

	templates[templateID] = struct{}{}

	if len(templates) >= d.threshold {
		d.flagged[normalized] = true
		return true
	}

	return false
}

// IsFlagged returns true if the given host has been flagged as a
// likely honeypot.
func (d *Detector) IsFlagged(host string) bool {
	if !d.Enabled() {
		return false
	}

	normalized := NormalizeHost(host)
	if normalized == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return d.flagged[normalized]
}

// MatchCount returns the number of distinct template matches
// recorded for a host.
func (d *Detector) MatchCount(host string) int {
	if !d.Enabled() {
		return 0
	}

	normalized := NormalizeHost(host)
	if normalized == "" {
		return 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.matches[normalized])
}

// FlaggedHosts returns a map of all flagged hosts to their
// match counts.
func (d *Detector) FlaggedHosts() map[string]int {
	if !d.Enabled() {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	result := make(map[string]int, len(d.flagged))
	for host := range d.flagged {
		result[host] = len(d.matches[host])
	}
	return result
}

// Summary returns a human-readable summary of honeypot detection
// results. If no hosts were flagged, an empty string is returned.
func (d *Detector) Summary() string {
	flagged := d.FlaggedHosts()
	if len(flagged) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[honeypot] %d host(s) flagged as likely honeypot:\n", len(flagged)))
	for host, count := range flagged {
		sb.WriteString(fmt.Sprintf("  - %s (%d template matches)\n", host, count))
	}
	return sb.String()
}

// NormalizeHost extracts a canonical host (host:port or just host)
// from various input formats: bare hosts, URLs, host:port, etc.
// IPv6 addresses are unwrapped from brackets.
func NormalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it looks like a URL, parse it
	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err != nil {
			return strings.ToLower(input)
		}
		host := parsed.Hostname()
		port := parsed.Port()
		if host == "" {
			return ""
		}
		if port != "" && port != "80" && port != "443" {
			return strings.ToLower(host + ":" + port)
		}
		return strings.ToLower(host)
	}

	// Handle bracketed IPv6 with or without port: [::1]:8080
	if strings.HasPrefix(input, "[") {
		// Try to find closing bracket
		closeBracket := strings.Index(input, "]")
		if closeBracket == -1 {
			return strings.ToLower(input)
		}
		host := input[1:closeBracket]
		rest := input[closeBracket+1:]
		if strings.HasPrefix(rest, ":") && len(rest) > 1 {
			port := rest[1:]
			if port != "80" && port != "443" {
				return strings.ToLower(host + ":" + port)
			}
		}
		return strings.ToLower(host)
	}

	// Strip trailing colon (e.g. "host:")
	input = strings.TrimRight(input, ":")

	// For bare host or host:port, just lowercase
	return strings.ToLower(input)
}
