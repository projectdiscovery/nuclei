package output

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan/honeypot"
)

// HoneypotWriter wraps an output.Writer and intercepts Write calls to
// track template matches per host for honeypot detection.
//
// When a host is detected as a potential honeypot, its results are annotated
// with a warning marker in the output. The writer tracks unique template IDs
// per normalized host and flags hosts that exceed the configured threshold.
type HoneypotWriter struct {
	// inner is the wrapped output writer.
	inner Writer

	// tracker is the honeypot detection tracker.
	tracker *honeypot.Tracker

	// colorizer is used for formatting warning output.
	colorizer aurora.Aurora

	// logger is used for warning messages.
	logger *gologger.Logger
}

var _ Writer = &HoneypotWriter{}

// NewHoneypotWriter creates a new HoneypotWriter wrapping the given writer.
func NewHoneypotWriter(inner Writer, tracker *honeypot.Tracker, colorizer aurora.Aurora, logger *gologger.Logger) *HoneypotWriter {
	return &HoneypotWriter{
		inner:     inner,
		tracker:   tracker,
		colorizer: colorizer,
		logger:    logger,
	}
}

// Close closes the inner writer.
func (hw *HoneypotWriter) Close() {
	hw.inner.Close()
}

// Colorizer returns the colorizer instance.
func (hw *HoneypotWriter) Colorizer() aurora.Aurora {
	return hw.inner.Colorizer()
}

// Write intercepts result events to track template matches per host.
// If the host has been flagged as a honeypot, the result is annotated
// but still written to allow users to see the data.
func (hw *HoneypotWriter) Write(event *ResultEvent) error {
	if event == nil {
		return nil
	}

	// Only track successful matches (MatcherStatus true or non-error results).
	if event.MatcherStatus || event.Error == "" {
		// Resolve the effective host, falling back to IP for IP-only results.
		host := event.Host
		if host == "" {
			host = event.IP
		}

		templateID := event.TemplateID

		if host != "" && templateID != "" {
			// Record the match. The tracker handles first-flag logging
			// internally, so no additional logging is needed here.
			hw.tracker.RecordMatch(host, templateID)
		}

		// Annotate the result if the host is a known honeypot.
		// Use the resolved host for consistent lookup.
		if host != "" && hw.tracker.IsHoneypot(host) {
			hw.annotateResult(event, host)
		}
	}

	return hw.inner.Write(event)
}

// WriteFailure passes failure events through to the inner writer.
func (hw *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return hw.inner.WriteFailure(event)
}

// Request passes request logs through to the inner writer.
func (hw *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	hw.inner.Request(templateID, url, requestType, err)
}

// WriteStoreDebugData passes debug data through to the inner writer.
func (hw *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	hw.inner.WriteStoreDebugData(host, templateID, eventType, data)
}

// RequestStatsLog passes stats log through to the inner writer.
func (hw *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	hw.inner.RequestStatsLog(statusCode, response)
}

// ResultCount returns the result count from the inner writer.
func (hw *HoneypotWriter) ResultCount() int {
	return hw.inner.ResultCount()
}

// Tracker returns the underlying honeypot tracker for summary access.
func (hw *HoneypotWriter) Tracker() *honeypot.Tracker {
	return hw.tracker
}

// annotateResult adds honeypot warning metadata to the result event.
// It uses the resolved host (which may be event.IP when event.Host is empty)
// to look up the correct match count. The TemplateID is left unmodified
// to avoid breaking JSONL, SARIF, or cloud consumers that key on it.
func (hw *HoneypotWriter) annotateResult(event *ResultEvent, resolvedHost string) {
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}

	matchCount := hw.tracker.GetMatchCount(resolvedHost)
	event.Metadata["honeypot_warning"] = true
	event.Metadata["honeypot_match_count"] = matchCount
	event.Metadata["honeypot_host"] = resolvedHost
}
