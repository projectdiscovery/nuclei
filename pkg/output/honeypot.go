package output

import (
	"net"
	"strings"
	"sync"

	urlutil "github.com/projectdiscovery/utils/url"
)

// honeypotDetector tracks per-host template matches and flags hosts that
// respond positively to an unusual number of distinct templates, which may
// indicate a honeypot or deceptive scanning environment.
type honeypotDetector struct {
	threshold   int                       // number of distinct templates before flagging
	suppress    bool                      // whether to suppress output for flagged hosts
	mu          sync.Mutex                // protects hostMatches and flagged
	hostMatches map[string]map[string]struct{} // host -> set of template IDs
	flagged     map[string]struct{}       // hosts that have crossed the threshold
}

// honeypotDecision holds the detector's evaluation result for a single event.
type honeypotDecision struct {
	host         string
	count        int
	newlyFlagged bool
	suppress     bool
}

// newHoneypotDetector creates a new honeypot detector with the given threshold and suppression flag.
// A threshold <= 0 disables detection entirely.
func newHoneypotDetector(threshold int, suppress bool) *honeypotDetector {
	if threshold <= 0 {
		return nil
	}
	return &honeypotDetector{
		threshold:   threshold,
		suppress:    suppress,
		hostMatches: make(map[string]map[string]struct{}),
		flagged:     make(map[string]struct{}),
	}
}

// evaluate processes a ResultEvent and returns a decision indicating whether the host
// is newly flagged, the current match count, and whether output should be suppressed.
func (d *honeypotDetector) evaluate(event *ResultEvent) honeypotDecision {
	if d == nil {
		return honeypotDecision{}
	}

	host := normalizeHoneypotHost(event)
	if host == "" {
		return honeypotDecision{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// If already flagged, return suppression decision immediately
	_, alreadyFlagged := d.flagged[host]
	if alreadyFlagged {
		return honeypotDecision{
			host:     host,
			suppress: d.suppress,
		}
	}

	// Track unique template IDs for this host
	templates, exists := d.hostMatches[host]
	if !exists {
		templates = make(map[string]struct{})
		d.hostMatches[host] = templates
	}
	templates[event.TemplateID] = struct{}{}
	count := len(templates)

	// Check if threshold crossed
	if count >= d.threshold {
		d.flagged[host] = struct{}{}
		// Free memory for this host's matches once flagged
		delete(d.hostMatches, host)
		return honeypotDecision{
			host:         host,
			count:        count,
			newlyFlagged: true,
			suppress:     false, // threshold-triggering event is visible
		}
	}

	return honeypotDecision{
		host:  host,
		count: count,
	}
}

// normalizeHoneypotHost extracts and normalizes a canonical host identifier from the event.
// It tries event.Host, event.URL, falling back to empty string if none are present.
func normalizeHoneypotHost(event *ResultEvent) string {
	for _, candidate := range []string{event.Host, event.URL} {
		host := normalizeHostCandidate(candidate)
		if host != "" {
			return host
		}
	}
	return ""
}

// normalizeHostCandidate attempts to extract a clean host from a candidate string
// (which may be a bare host, host:port, or URL) and normalizes it to lowercase.
func normalizeHostCandidate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	// Fallback: strip any scheme prefix generically first (e.g., HTTPS://host, tcp://host)
	// This handles uppercase schemes and non-HTTP schemes
	if idx := strings.Index(value, "://"); idx >= 0 {
		value = value[idx+3:]
	}

	// Try parsing as URL (handles http://host:port/path)
	if parsed, err := urlutil.ParseAbsoluteURL(value, false); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}

	// Try stripping port (handles host:port or [::1]:port)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		// Handle bare IPv6 with brackets: [::1] -> ::1
		value = strings.TrimPrefix(value, "[")
		value = strings.TrimSuffix(value, "]")
	}

	value = strings.TrimSpace(value)
	value = strings.ToLower(value)

	return value
}
