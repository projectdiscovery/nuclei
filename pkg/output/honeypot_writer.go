// Package output provides output writing functionality for nuclei scan results.
// This file contains the HoneypotWriter which wraps standard output writers
// to intercept results and track them for honeypot detection.
package output

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotdetection"
)

// HoneypotWriter wraps an output Writer to enable honeypot detection.
// It intercepts all Write calls to record template matches for honeypot analysis
// while delegating the actual output to the underlying writer.
// This allows transparent honeypot detection without modifying existing output logic.
type HoneypotWriter struct {
	// writer is the underlying output writer that handles actual output
	writer Writer
	// honeypot is the cache used for tracking matches and detecting honeypots
	honeypot *honeypotdetection.Cache
}

// NewHoneypotWriter creates a new HoneypotWriter that wraps the given writer.
// All write operations will be intercepted to record matches for honeypot detection,
// then forwarded to the underlying writer.
// The honeypotCache parameter must not be nil for honeypot detection to work.
func NewHoneypotWriter(writer Writer, honeypotCache *honeypotdetection.Cache) *HoneypotWriter {
	return &HoneypotWriter{
		writer:   writer,
		honeypot: honeypotCache,
	}
}

// Close closes the underlying writer and releases any resources.
// This should be called when output is complete.
func (h *HoneypotWriter) Close() {
	h.writer.Close()
}

// Colorizer returns the aurora colorizer instance from the underlying writer.
// This is used for colorized terminal output.
func (h *HoneypotWriter) Colorizer() aurora.Aurora {
	return h.writer.Colorizer()
}

// Write writes the event to output and records it for honeypot detection.
// The match is recorded in the honeypot cache before being written to the underlying writer.
// This allows the honeypot detection system to track which templates match which hosts.
// Returns any error from the underlying writer.
func (h *HoneypotWriter) Write(event *ResultEvent) error {
	// Record the match for honeypot detection before writing
	if h.honeypot != nil && event != nil {
		h.honeypot.RecordMatch(event.Host, event.TemplateID, event.URL)
	}

	// Write to the underlying writer
	return h.writer.Write(event)
}

// WriteFailure writes a failure event to the underlying writer.
// Failure events are not recorded for honeypot detection as they represent
// templates that did not match, not positive detections.
func (h *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return h.writer.WriteFailure(event)
}

// Request logs a request in the trace log via the underlying writer.
// This is used for debugging and request tracking purposes.
// The templateID, url, and requestType identify the request being logged.
// The err parameter captures any error that occurred during the request.
func (h *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	h.writer.Request(templateID, url, requestType, err)
}

// RequestStatsLog logs request statistics via the underlying writer.
// This is used for tracking HTTP response statistics.
// The statusCode is the HTTP status code received.
// The response contains response metadata for logging.
func (h *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	h.writer.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData writes request/response debug data to file via the underlying writer.
// This is used for storing detailed request/response data for debugging.
// The host, templateID, and eventType identify the context of the debug data.
// The data parameter contains the actual debug information to store.
func (h *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	h.writer.WriteStoreDebugData(host, templateID, eventType, data)
}

// ResultCount returns the total number of results written via the underlying writer.
// This count represents successful matches that were output.
func (h *HoneypotWriter) ResultCount() int {
	return h.writer.ResultCount()
}

// Ensure HoneypotWriter implements Writer interface at compile time.
// This compile-time check ensures that HoneypotWriter correctly implements
// all methods required by the Writer interface.
var _ Writer = (*HoneypotWriter)(nil)
