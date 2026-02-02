package output

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

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
// Features:
//   - Marks honeypot-originated results with HoneypotHost field for JSON output
//   - Optional suppression of results from detected honeypots
//   - Export detected honeypots to file for blocklist creation
//   - Enhanced statistics including suppression counts
type HoneypotWriter struct {
	// writer is the underlying output writer being wrapped
	writer Writer
	// detector is the honeypot detection engine
	detector *honeypotdetector.Detector
	// suppress controls whether results from honeypots are suppressed
	suppress bool
	// verbose enables verbose logging output
	verbose bool

	// exportPath is the file path to export honeypot hosts (optional)
	exportPath string

	// warnedMu protects the warned map for concurrent access
	warnedMu sync.RWMutex
	// warned tracks which hosts we have already warned about
	warned map[string]bool

	// suppressedCount is an atomic counter for suppressed results
	suppressedCount int64
}

// NewHoneypotWriter creates a new honeypot-aware output writer.
// It wraps the provided writer and uses the detector to identify honeypot hosts.
// If suppress is true, results from detected honeypots will not be written.
// If exportPath is non-empty, detected honeypots will be written to that file on Close.
func NewHoneypotWriter(writer Writer, detector *honeypotdetector.Detector, suppress, verbose bool, exportPath string) *HoneypotWriter {
	return &HoneypotWriter{
		writer:     writer,
		detector:   detector,
		suppress:   suppress,
		verbose:    verbose,
		exportPath: exportPath,
		warned:     make(map[string]bool),
	}
}

// Write processes a result event, checking for honeypot behavior.
// If a host is flagged as a honeypot and suppression is enabled, the result is dropped.
// Otherwise, a warning is logged when a host crosses the honeypot threshold.
// Note: The match that crosses the threshold is still written (with warning).
// Only subsequent matches are suppressed if suppression is enabled.
// The HoneypotHost field is set on events from flagged hosts for JSON output.
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
		// Mark this event as coming from a honeypot host (for JSON output)
		event.HoneypotHost = true
		event.HoneypotMatchCount = w.detector.GetMatchCount(host)

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
			atomic.AddInt64(&w.suppressedCount, 1)
			return nil
		}
	}

	return w.writer.Write(event)
}

// WriteFailure delegates to the underlying writer.
func (w *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return w.writer.WriteFailure(event)
}

// Close closes the writer, logs honeypot detection summary, and exports honeypots to file if configured.
func (w *HoneypotWriter) Close() {
	if w.detector != nil {
		count := w.detector.GetHoneypotCount()
		suppressedCount := atomic.LoadInt64(&w.suppressedCount)
		flaggedHosts := w.detector.GetFlaggedHosts()

		if count > 0 {
			// Log enhanced summary with suppression stats
			if suppressedCount > 0 {
				gologger.Info().Msgf("Honeypot detection summary: %d host(s) flagged, %d result(s) suppressed", count, suppressedCount)
			} else {
				gologger.Info().Msgf("Honeypot detection summary: %d host(s) flagged as potential honeypots", count)
			}

			if w.verbose {
				for _, host := range flaggedHosts {
					gologger.Verbose().Msgf("  - %s (%d templates matched)", host, w.detector.GetMatchCount(host))
				}
			}

			// Export honeypots to file if path is configured
			if w.exportPath != "" {
				if err := w.exportHoneypots(flaggedHosts); err != nil {
					gologger.Warning().Msgf("Failed to export honeypots to %s: %v", w.exportPath, err)
				} else {
					gologger.Info().Msgf("Exported %d honeypot host(s) to %s", count, w.exportPath)
				}
			}
		}
		w.detector.Close()
	}
	w.writer.Close()
}

// exportHoneypots writes the flagged honeypot hosts to the configured export file.
// Format: host,match_count (CSV-like for easy parsing by other tools)
// Lines starting with # are treated as comments when re-imported.
func (w *HoneypotWriter) exportHoneypots(hosts []string) error {
	f, err := os.Create(w.exportPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header comment
	if _, err := f.WriteString("# Honeypot hosts detected by nuclei\n"); err != nil {
		return err
	}
	if _, err := f.WriteString("# Format: host,match_count\n"); err != nil {
		return err
	}

	for _, host := range hosts {
		matchCount := w.detector.GetMatchCount(host)
		// Write in format: host,count for easy parsing
		line := fmt.Sprintf("%s,%d\n", host, matchCount)
		if _, err := f.WriteString(line); err != nil {
			return err
		}
		// Also log details in verbose mode
		if w.verbose {
			gologger.Verbose().Msgf("Exported: %s (%d templates)", host, matchCount)
		}
	}
	return nil
}

// GetSuppressedCount returns the number of results that were suppressed due to honeypot detection.
func (w *HoneypotWriter) GetSuppressedCount() int64 {
	return atomic.LoadInt64(&w.suppressedCount)
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
