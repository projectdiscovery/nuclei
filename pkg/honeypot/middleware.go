package honeypot

import (
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Middleware wraps an output Writer to intercept results and perform honeypot
// detection before writing. This allows honeypot warnings to be emitted without
// blocking or modifying the actual findings.
type Middleware struct {
	writer   output.Writer
	detector *Detector
	logger   *gologger.Logger
	mode     DetectionMode
}

// NewMiddleware creates a new honeypot detection middleware wrapping a Writer.
//
// Parameters:
//   - writer: the underlying output writer to wrap
//   - enabled: whether detection is active
//   - mode: the action to take when a honeypot is detected (warn, tag, suppress)
//   - logger: logger for warnings
//
// The middleware is non-blocking: it always writes results but may emit warnings
// or tag findings depending on the mode.
func NewMiddleware(writer output.Writer, enabled bool, mode string, logger *gologger.Logger) *Middleware {
	if logger == nil {
		logger = gologger.DefaultLogger
	}

	// Normalize mode string
	detMode := DetectionMode(strings.ToLower(mode))
	if detMode != ModeWarn && detMode != ModeTag && detMode != ModeSuppress {
		detMode = ModeWarn // Default to warn for invalid modes
	}

	return &Middleware{
		writer: writer,
		detector: New(Config{
			Enabled: enabled,
			Mode:    detMode,
			Logger: func(msg string) {
				logger.Warning().Msg(msg)
			},
		}),
		logger: logger,
		mode:   detMode,
	}
}

// Write implements the output.Writer interface, intercepting ResultEvent to
// perform honeypot detection before writing.
func (m *Middleware) Write(event *output.ResultEvent) error {
	if event == nil {
		return m.writer.Write(event)
	}

	// Record the match for honeypot analysis
	m.detector.recordMatch(event.Host, event)

	// Check if this host is flagged as a honeypot
	isHoneypot, report := m.detector.IsHoneypot(event.Host)

	// Handle suppression mode
	if isHoneypot && m.mode == ModeSuppress {
		m.logger.Warning().Msgf("Suppressing result from honeypot: %s", event.Host)
		return nil // Don't write the result
	}

	// Handle tag mode: mark event with honeypot metadata
	if isHoneypot && m.mode == ModeTag {
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		event.Metadata["honeypot"] = true

		m.logger.Warning().Msgf("Result from potential honeypot host (tagged): %s", event.Host)
	}

	// Handle warn mode (or default for tag mode)
	if isHoneypot && m.mode == ModeWarn {
		m.logger.Warning().Msg(report.String())
	}

	// Always write the result (unless suppressed above)
	return m.writer.Write(event)
}

// Close closes the underlying writer
func (m *Middleware) Close() {
	m.writer.Close()
}

// Colorizer returns the colorizer from the underlying writer
func (m *Middleware) Colorizer() aurora.Aurora {
	return m.writer.Colorizer()
}

// WriteFailure writes a failure event
func (m *Middleware) WriteFailure(event *output.InternalWrappedEvent) error {
	return m.writer.WriteFailure(event)
}

// Request logs a request in the trace log
func (m *Middleware) Request(templateID, url, requestType string, err error) {
	m.writer.Request(templateID, url, requestType, err)
}

// RequestStatsLog logs a request stats log
func (m *Middleware) RequestStatsLog(statusCode, response string) {
	m.writer.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData writes the request/response debug data to file
func (m *Middleware) WriteStoreDebugData(host, templateID, eventType string, data string) {
	m.writer.WriteStoreDebugData(host, templateID, eventType, data)
}

// ResultCount returns the total number of results written
func (m *Middleware) ResultCount() int {
	return m.writer.ResultCount()
}

// GetDetector returns the underlying detector for testing or introspection
func (m *Middleware) GetDetector() *Detector {
	return m.detector
}
