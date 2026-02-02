package output

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotdetector"
)

// normalizeHost extracts a consistent host identifier from various input formats.
// This ensures that the same host with different ports or paths is tracked as one.
// Handles IPv4, IPv6, and various URL formats correctly.
// Examples:
//   - "https://example.com:8443/path" -> "example.com"
//   - "http://120.26.237.211:80/foo" -> "120.26.237.211"
//   - "[::1]:8080" -> "::1"
//   - "example.com" -> "example.com"
func normalizeHost(host, urlField string) string {
	// Prefer Host field if available
	if host != "" {
		// Use net.SplitHostPort for proper IPv4/IPv6 handling
		if h, _, err := net.SplitHostPort(host); err == nil {
			return strings.ToLower(h)
		}
		// No port, return as-is
		return strings.ToLower(host)
	}

	// Fall back to URL field
	if urlField == "" {
		return ""
	}

	// Try to parse as URL
	parsed, err := url.Parse(urlField)
	if err == nil && parsed.Host != "" {
		// Hostname() handles IPv6 brackets correctly
		return strings.ToLower(parsed.Hostname())
	}

	// If parsing fails, return as-is (lowercase)
	return strings.ToLower(urlField)
}

// HoneypotWriter is a wrapper around a Writer that performs honeypot detection.
// It tracks template matches per host and can warn or suppress results from
// hosts that match an unusually high number of templates (indicative of honeypots).
type HoneypotWriter struct {
	writer   Writer
	detector *honeypotdetector.Detector
	suppress bool
	verbose  bool

	warnedMu sync.RWMutex
	warned   map[string]bool // track which hosts we have warned about
}

// NewHoneypotWriter creates a new honeypot-aware output writer.
// It wraps the provided writer and uses the detector to identify honeypot hosts.
// If suppress is true, results from detected honeypots will not be written.
func NewHoneypotWriter(writer Writer, detector *honeypotdetector.Detector, suppress, verbose bool) *HoneypotWriter {
	return &HoneypotWriter{
		writer:   writer,
		detector: detector,
		suppress: suppress,
		verbose:  verbose,
		warned:   make(map[string]bool),
	}
}

// Write processes a result event, checking for honeypot behavior.
// If a host is flagged as a honeypot and suppression is enabled, the result is dropped.
// Otherwise, a warning is logged when a host crosses the honeypot threshold.
// Note: The match that crosses the threshold is still written (with warning).
// Only subsequent matches are suppressed if suppression is enabled.
func (w *HoneypotWriter) Write(event *ResultEvent) error {
	if w.detector == nil {
		return w.writer.Write(event)
	}

	// Normalize the host to handle different ports/paths pointing to same server
	host := normalizeHost(event.Host, event.URL)
	if host == "" {
		// Fallback to original fields if normalization returns empty
		host = event.Host
		if host == "" {
			host = event.URL
		}
	}

	// Check if already flagged BEFORE recording this match
	wasAlreadyFlagged := w.detector.IsHoneypot(host)

	// Record this match and check if honeypot threshold is crossed
	isHoneypot := w.detector.RecordMatch(host, event.TemplateID)

	if isHoneypot {
		// Log warning only once per host (thread-safe)
		w.warnedMu.RLock()
		alreadyWarned := w.warned[host]
		w.warnedMu.RUnlock()

		if !alreadyWarned {
			w.warnedMu.Lock()
			// Double-check after acquiring write lock
			if !w.warned[host] {
				w.warned[host] = true
				matchCount := w.detector.GetMatchCount(host)
				gologger.Warning().Msgf("Potential honeypot detected: %s (matched %d distinct templates)", host, matchCount)
				if w.suppress {
					gologger.Info().Msgf("Future results from %s will be suppressed", host)
				}
			}
			w.warnedMu.Unlock()
		}

		// If suppression is enabled, suppress ONLY if this host was already flagged before this match
		// This allows the threshold-crossing match to be reported with the warning
		if w.suppress && wasAlreadyFlagged {
			return nil
		}
	}

	return w.writer.Write(event)
}

// WriteFailure delegates to the underlying writer.
func (w *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return w.writer.WriteFailure(event)
}

// Close closes the writer and logs honeypot detection summary.
func (w *HoneypotWriter) Close() {
	if w.detector != nil {
		count := w.detector.GetHoneypotCount()
		if count > 0 {
			gologger.Info().Msgf("Honeypot detection summary: %d host(s) flagged as potential honeypots", count)
			if w.verbose {
				for _, host := range w.detector.GetFlaggedHosts() {
					gologger.Verbose().Msgf("  - %s (%d templates matched)", host, w.detector.GetMatchCount(host))
				}
			}
		}
		w.detector.Close()
	}
	w.writer.Close()
}

// Colorizer returns the colorizer from the underlying writer.
func (w *HoneypotWriter) Colorizer() aurora.Aurora {
	return w.writer.Colorizer()
}

// Request delegates to the underlying writer.
func (w *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	w.writer.Request(templateID, url, requestType, err)
}

// RequestStatsLog delegates to the underlying writer.
func (w *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	w.writer.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData delegates to the underlying writer.
func (w *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	w.writer.WriteStoreDebugData(host, templateID, eventType, data)
}

// ResultCount returns the count from the underlying writer.
func (w *HoneypotWriter) ResultCount() int {
	return w.writer.ResultCount()
}

// GetDetector returns the honeypot detector for external access (e.g., for summary reporting).
func (w *HoneypotWriter) GetDetector() *honeypotdetector.Detector {
	return w.detector
}

var _ Writer = &HoneypotWriter{}
