package output

import (
	"net"
	"net/url"
	"sync"

	"github.com/projectdiscovery/gologger"
)

const defaultHoneypotThreshold = 10

// HoneypotTracker tracks unique template matches per host to detect honeypots.
// Hosts that match more than the configured threshold of unique templates are
// flagged as honeypots and their results are suppressed.
type HoneypotTracker struct {
	mu        sync.Mutex
	hosts     map[string]map[string]struct{} // host -> set of template IDs
	flagged   map[string]struct{}            // hosts already flagged
	threshold int
}

// NewHoneypotTracker creates a new tracker with the given threshold.
// If threshold <= 0, defaultHoneypotThreshold is used.
func NewHoneypotTracker(threshold int) *HoneypotTracker {
	if threshold <= 0 {
		threshold = defaultHoneypotThreshold
	}
	return &HoneypotTracker{
		hosts:     make(map[string]map[string]struct{}),
		flagged:   make(map[string]struct{}),
		threshold: threshold,
	}
}

// Check records a template match for the given host and returns true if the
// result should be suppressed (host is a honeypot).
func (h *HoneypotTracker) Check(host, templateID string) bool {
	normalized := normalizeHost(host)

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.flagged[normalized]; ok {
		return true
	}

	templates, ok := h.hosts[normalized]
	if !ok {
		templates = make(map[string]struct{})
		h.hosts[normalized] = templates
	}

	templates[templateID] = struct{}{}

	if len(templates) >= h.threshold {
		h.flagged[normalized] = struct{}{}
		delete(h.hosts, normalized) // free memory, no longer need per-template tracking
		gologger.Warning().Msgf("Honeypot detected: %s (%d unique template matches, suppressing further results)", host, len(templates))
		return true
	}

	return false
}

// normalizeHost extracts a consistent host identifier from various input formats.
func normalizeHost(raw string) string {
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		host := parsed.Hostname() // strips brackets from IPv6, strips port
		if host != "" {
			return host
		}
	}
	// Fallback: try as host:port
	host, _, err := net.SplitHostPort(raw)
	if err == nil && host != "" {
		return host
	}
	return raw
}
