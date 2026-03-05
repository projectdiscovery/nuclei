package output

import (
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/honeypot"
)

// mockWriter is a minimal Writer that records calls.
type mockWriter struct {
	writtenEvents []*ResultEvent
	closeCalled   bool
}

func (m *mockWriter) Close()                                                       { m.closeCalled = true }
func (m *mockWriter) Colorizer() aurora.Aurora                                     { return aurora.NewAurora(false) }
func (m *mockWriter) WriteFailure(event *InternalWrappedEvent) error               { return nil }
func (m *mockWriter) Request(templateID, url, requestType string, err error)       {}
func (m *mockWriter) RequestStatsLog(statusCode, response string)                  {}
func (m *mockWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
func (m *mockWriter) ResultCount() int                                             { return len(m.writtenEvents) }

func (m *mockWriter) Write(event *ResultEvent) error {
	m.writtenEvents = append(m.writtenEvents, event)
	return nil
}

// TestHoneypotWriterPassthrough verifies that results pass through
// when the host is not flagged.
func TestHoneypotWriterPassthrough(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypot.New(5)
	writer := NewHoneypotWriter(mock, detector)

	event := &ResultEvent{
		Host:       "clean-host.com",
		TemplateID: "tmpl-1",
	}
	if err := writer.Write(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.writtenEvents) != 1 {
		t.Fatalf("expected 1 event passed through, got %d", len(mock.writtenEvents))
	}
}

// TestHoneypotWriterSuppression verifies that results are suppressed
// once a host exceeds the threshold.
func TestHoneypotWriterSuppression(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypot.New(3)
	writer := NewHoneypotWriter(mock, detector)

	// Send 3 different template matches for the same host
	for i := 0; i < 3; i++ {
		event := &ResultEvent{
			Host:       "honeypot.example.com",
			TemplateID: "tmpl-" + string(rune('a'+i)),
		}
		_ = writer.Write(event)
	}

	// First 2 should pass through, 3rd triggers flagging and is suppressed
	if len(mock.writtenEvents) != 2 {
		t.Fatalf("expected 2 events passed through (3rd suppressed), got %d", len(mock.writtenEvents))
	}

	// Additional events should also be suppressed
	event := &ResultEvent{
		Host:       "honeypot.example.com",
		TemplateID: "tmpl-d",
	}
	_ = writer.Write(event)
	if len(mock.writtenEvents) != 2 {
		t.Fatalf("expected still 2 events after additional write, got %d", len(mock.writtenEvents))
	}
}

// TestHoneypotWriterDisabledPassthrough verifies that when the
// detector is disabled, NewHoneypotWriter returns the inner writer directly.
func TestHoneypotWriterDisabledPassthrough(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypot.New(0) // disabled
	writer := NewHoneypotWriter(mock, detector)

	// Should be the mock itself, not wrapped
	if _, ok := writer.(*HoneypotWriter); ok {
		t.Fatal("expected inner writer to be returned when detector is disabled")
	}
}

// TestHoneypotWriterUsesURLFallback verifies that the writer falls
// back to the URL field when Host is empty.
func TestHoneypotWriterUsesURLFallback(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypot.New(2)
	writer := NewHoneypotWriter(mock, detector)

	// Use URL instead of Host
	for i := 0; i < 3; i++ {
		event := &ResultEvent{
			URL:        "http://fallback-host.com/path",
			TemplateID: "tmpl-" + string(rune('a'+i)),
		}
		_ = writer.Write(event)
	}

	// First event passes, second triggers flagging
	if len(mock.writtenEvents) != 1 {
		t.Fatalf("expected 1 event passed through with URL fallback, got %d", len(mock.writtenEvents))
	}
}

// TestHoneypotWriterNoHostPassthrough verifies that events with no
// host information always pass through.
func TestHoneypotWriterNoHostPassthrough(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypot.New(1) // Very low threshold
	writer := NewHoneypotWriter(mock, detector)

	event := &ResultEvent{
		TemplateID: "tmpl-1",
		// No Host or URL
	}
	if err := writer.Write(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.writtenEvents) != 1 {
		t.Fatalf("expected event with no host to pass through")
	}
}
