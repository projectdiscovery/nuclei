package output

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotdetection"
)

// HoneypotWriter wraps an output Writer to enable honeypot detection
type HoneypotWriter struct {
	writer   Writer
	honeypot *honeypotdetection.Cache
}

// NewHoneypotWriter creates a new HoneypotWriter wrapping the given writer
func NewHoneypotWriter(writer Writer, honeypotCache *honeypotdetection.Cache) *HoneypotWriter {
	return &HoneypotWriter{
		writer:   writer,
		honeypot: honeypotCache,
	}
}

// Close closes the underlying writer
func (h *HoneypotWriter) Close() {
	h.writer.Close()
}

// Colorizer returns the colorizer instance
func (h *HoneypotWriter) Colorizer() aurora.Aurora {
	return h.writer.Colorizer()
}

// Write writes the event and records it for honeypot detection
func (h *HoneypotWriter) Write(event *ResultEvent) error {
	// Record the match for honeypot detection before writing
	if h.honeypot != nil && event != nil {
		h.honeypot.RecordMatch(event.Host, event.TemplateID, event.URL)
	}

	// Write to the underlying writer
	return h.writer.Write(event)
}

// WriteFailure writes the failure event
func (h *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return h.writer.WriteFailure(event)
}

// Request logs a request in the trace log
func (h *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	h.writer.Request(templateID, url, requestType, err)
}

// RequestStatsLog logs a request stats log
func (h *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	h.writer.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData writes the request/response debug data to file
func (h *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	h.writer.WriteStoreDebugData(host, templateID, eventType, data)
}

// ResultCount returns the total number of results written
func (h *HoneypotWriter) ResultCount() int {
	return h.writer.ResultCount()
}

// Ensure HoneypotWriter implements Writer interface
var _ Writer = (*HoneypotWriter)(nil)
