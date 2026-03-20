package honeypot

import (
	"fmt"
	"sort"
	"net"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

const (
	// DefaultThreshold is the default number of distinct template matches
	// per host before flagging it as a potential honeypot.
	DefaultThreshold = 100
)

// Detector tracks per-host template match counts and flags hosts
// that exceed a configurable threshold as potential honeypots.
// Honeypots (e.g. on Shodan) mimic vulnerable services and match
// many nuclei templates, producing a flood of false positives.
//
// The detector is safe for concurrent use.
type Detector struct {
	mu        sync.RWMutex
	threshold int
	suppress  bool
	// hosts maps normalized host -> set of matched template IDs
	hosts map[string]map[string]struct{}
	// flagged tracks hosts that crossed the threshold
	flagged map[string]bool
	// warned tracks hosts for which a warning was already printed
	warned map[string]bool
}

// New creates a new honeypot Detector.
//
// threshold sets how many distinct template IDs must match a single host
// before it is flagged. Use DefaultThreshold if unsure.
//
// suppress controls whether results from flagged hosts are dropped (true)
// or only annotated with a warning (false).
func New(threshold int, suppress bool) *Detector {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Detector{
		threshold: threshold,
		suppress:  suppress,
		hosts:     make(map[string]map[string]struct{}),
		flagged:   make(map[string]bool),
		warned:    make(map[string]bool),
	}
}

// RecordMatch registers that templateID matched against host.
// It returns true if the host is now (or was already) flagged as a
// potential honeypot.
func (d *Detector) RecordMatch(host, templateID string) bool {
	key := normalizeHost(host)
	if key == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Already flagged — skip further tracking
	if d.flagged[key] {
		return true
	}

	templates, ok := d.hosts[key]
	if !ok {
		templates = make(map[string]struct{})
		d.hosts[key] = templates
	}
	templates[templateID] = struct{}{}

	if len(templates) >= d.threshold {
		d.flagged[key] = true
		// Free the per-template set — we no longer need it
		delete(d.hosts, key)
		d.emitWarning(key, len(templates))
		return true
	}
	return false
}

// IsFlagged reports whether the host has been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	key := normalizeHost(host)
	if key == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.flagged[key]
}

// ShouldSuppress reports whether results for the given host should be
// dropped from output. This is true only when the host is flagged AND
// the detector was created with suppress=true.
func (d *Detector) ShouldSuppress(host string) bool {
	if !d.suppress {
		return false
	}
	return d.IsFlagged(host)
}

// MatchCount returns the number of distinct template IDs matched for
// the given host. After a host is flagged the exact count is no longer
// tracked and -1 is returned.
func (d *Detector) MatchCount(host string) int {
	key := normalizeHost(host)
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.flagged[key] {
		return -1
	}
	return len(d.hosts[key])
}

// Summary returns all flagged hosts.
func (d *Detector) Summary() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make([]string, 0, len(d.flagged))
	for host := range d.flagged {
		result = append(result, host)
	}
	return result
}

// emitWarning prints a one-time warning to gologger for the flagged host.
// Must be called with d.mu held.
func (d *Detector) emitWarning(host string, matchCount int) {
	if d.warned[host] {
		return
	}
	d.warned[host] = true
	action := "results will still be shown"
	if d.suppress {
		action = "further results will be suppressed"
	}
	gologger.Warning().Msgf(
		"[honeypot] %s matched %d+ distinct templates (threshold: %d) — possible honeypot, %s",
		host, matchCount, d.threshold, action,
	)
}

// normalizeHost extracts a canonical host key from various input formats
// (URL, host:port, bare IP, IPv6, etc.).
func normalizeHost(raw string) string {
	if raw == "" {
		return ""
	}

	s := raw
	// Strip scheme
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	// Strip path/query
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	// Strip userinfo
	if idx := strings.LastIndex(s, "@"); idx != -1 {
		s = s[idx+1:]
	}

	// Handle IPv6 bracket notation [::1]:port
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end != -1 {
			ipv6 := s[1:end]
			parsed := net.ParseIP(ipv6)
			if parsed != nil {
				return parsed.String()
			}
			return ipv6
		}
	}

	// Try host:port split
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		s = host
	}

	// Normalize IP if possible
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}

	return strings.ToLower(s)
}

// FormatSummary returns a human-readable summary of all flagged hosts.
func (d *Detector) FormatSummary() string {
	flagged := d.Summary()
	sort.Strings(flagged)
	if len(flagged) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n[honeypot] %d host(s) flagged as potential honeypots:\n", len(flagged)))
	for _, h := range flagged {
		b.WriteString(fmt.Sprintf("  - %s\n", h))
	}
	if d.suppress {
		b.WriteString("[honeypot] Results from these hosts were suppressed.\n")
	} else {
		b.WriteString("[honeypot] Results from these hosts may contain false positives.\n")
	}
	return b.String()
}
