package output

import (
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotdetector"
)

// mockWriter is a simple mock for testing the HoneypotWriter
type mockWriter struct {
	results       []*ResultEvent
	failures      []*InternalWrappedEvent
	closed        bool
	resultCounter int
}

func (m *mockWriter) Close()                   { m.closed = true }
func (m *mockWriter) Colorizer() aurora.Aurora { return aurora.NewAurora(false) }
func (m *mockWriter) Write(event *ResultEvent) error {
	m.results = append(m.results, event)
	m.resultCounter++
	return nil
}
func (m *mockWriter) WriteFailure(event *InternalWrappedEvent) error {
	m.failures = append(m.failures, event)
	return nil
}
func (m *mockWriter) Request(templateID, url, requestType string, err error)       {}
func (m *mockWriter) RequestStatsLog(statusCode, response string)                  {}
func (m *mockWriter) WriteStoreDebugData(host, templateID, eventType, data string) {}
func (m *mockWriter) ResultCount() int                                             { return m.resultCounter }

var _ Writer = &mockWriter{}

func TestHoneypotWriterPassthrough(t *testing.T) {
	// Test that results pass through when under threshold
	mock := &mockWriter{}
	detector := honeypotdetector.New(5, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false)

	// Write 4 results (under threshold of 5)
	for i := 0; i < 4; i++ {
		event := &ResultEvent{
			Host:       "example.com",
			TemplateID: "template-" + string(rune('a'+i)),
		}
		if err := writer.Write(event); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	if len(mock.results) != 4 {
		t.Errorf("Expected 4 results, got %d", len(mock.results))
	}

	if detector.IsHoneypot("example.com") {
		t.Error("Host should not be flagged as honeypot yet")
	}
}

func TestHoneypotWriterDetection(t *testing.T) {
	// Test that honeypots are detected at threshold
	mock := &mockWriter{}
	detector := honeypotdetector.New(3, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false)

	// Write 3 results with different templates (hits threshold)
	for i := 0; i < 3; i++ {
		event := &ResultEvent{
			Host:       "honeypot.com",
			TemplateID: "vuln-cve-" + string(rune('1'+i)),
		}
		writer.Write(event)
	}

	if !detector.IsHoneypot("honeypot.com") {
		t.Error("Host should be flagged as honeypot")
	}

	// Results should still be written (suppression is false)
	if len(mock.results) != 3 {
		t.Errorf("Expected 3 results (no suppression), got %d", len(mock.results))
	}
}

func TestHoneypotWriterSuppression(t *testing.T) {
	// Test that results are suppressed after honeypot detection
	mock := &mockWriter{}
	detector := honeypotdetector.New(3, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false) // suppression ON

	// Write 5 results: first 2 are under threshold, 3rd crosses threshold (still written), 4th and 5th suppressed
	for i := 0; i < 5; i++ {
		event := &ResultEvent{
			Host:       "honeypot.com",
			TemplateID: "template-" + string(rune('a'+i)),
		}
		writer.Write(event)
	}

	// With new semantics: 1st, 2nd written (under threshold), 3rd crosses threshold AND is written (with warning)
	// 4th, 5th are suppressed (host was already flagged)
	if len(mock.results) != 3 {
		t.Errorf("Expected 3 results (threshold-crossing match passes through), got %d", len(mock.results))
	}

	if detector.GetHoneypotCount() != 1 {
		t.Errorf("Expected 1 honeypot, got %d", detector.GetHoneypotCount())
	}
}

func TestHoneypotWriterMultipleHosts(t *testing.T) {
	// Test that detection works correctly across multiple hosts
	mock := &mockWriter{}
	detector := honeypotdetector.New(2, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false)

	// Host A: 2 templates (flagged)
	writer.Write(&ResultEvent{Host: "hostA.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "hostA.com", TemplateID: "t2"})

	// Host B: 1 template (not flagged)
	writer.Write(&ResultEvent{Host: "hostB.com", TemplateID: "t1"})

	// Host C: 2 templates (flagged)
	writer.Write(&ResultEvent{Host: "hostC.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "hostC.com", TemplateID: "t2"})

	if detector.GetHoneypotCount() != 2 {
		t.Errorf("Expected 2 honeypots (A and C), got %d", detector.GetHoneypotCount())
	}

	// With new semantics: threshold-crossing match passes through
	// Host A: 2 written (1st under threshold, 2nd crosses and passes with warning)
	// Host B: 1 written (not flagged)
	// Host C: 2 written (1st under threshold, 2nd crosses and passes with warning)
	// Total: 5 results
	if len(mock.results) != 5 {
		t.Errorf("Expected 5 results (threshold-crossing matches pass), got %d", len(mock.results))
	}
}

func TestHoneypotWriterNilDetector(t *testing.T) {
	// Test graceful handling when detector is nil
	mock := &mockWriter{}
	writer := NewHoneypotWriter(mock, nil, false, false)

	event := &ResultEvent{Host: "example.com", TemplateID: "test"}
	if err := writer.Write(event); err != nil {
		t.Fatalf("Write with nil detector failed: %v", err)
	}

	if len(mock.results) != 1 {
		t.Error("Result should pass through when detector is nil")
	}
}

func TestHoneypotWriterURLFallback(t *testing.T) {
	// Test that URL is used when Host is empty
	mock := &mockWriter{}
	detector := honeypotdetector.New(2, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false)

	// Use URL instead of Host, with path - should normalize to just hostname
	writer.Write(&ResultEvent{URL: "https://example.com/path1", TemplateID: "t1"})
	writer.Write(&ResultEvent{URL: "https://example.com/path2", TemplateID: "t2"})

	// Should detect honeypot using normalized hostname
	if !detector.IsHoneypot("example.com") {
		t.Error("Should detect honeypot using normalized hostname from URL")
	}
}

func TestHoneypotWriterPortNormalization(t *testing.T) {
	// Test that the same IP with different ports is treated as the same host
	// This is critical for detecting honeypots on Shodan that respond on multiple ports
	mock := &mockWriter{}
	detector := honeypotdetector.New(3, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false)

	// Same IP, different ports - should all be tracked as 120.26.237.211
	writer.Write(&ResultEvent{URL: "http://120.26.237.211:80/path", TemplateID: "cve-2021-1234"})
	writer.Write(&ResultEvent{URL: "http://120.26.237.211:8080/admin", TemplateID: "cve-2022-5678"})
	writer.Write(&ResultEvent{URL: "http://120.26.237.211:12577/api", TemplateID: "cve-2023-9999"})

	// All 3 should map to same normalized host
	if !detector.IsHoneypot("120.26.237.211") {
		t.Error("Should detect honeypot when same IP with different ports matches many templates")
	}

	if detector.GetMatchCount("120.26.237.211") != 3 {
		t.Errorf("Expected 3 matches for normalized IP, got %d", detector.GetMatchCount("120.26.237.211"))
	}
}

func TestHoneypotWriterIPv6Normalization(t *testing.T) {
	// Test that IPv6 addresses are properly normalized
	mock := &mockWriter{}
	detector := honeypotdetector.New(2, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false)

	// IPv6 addresses with brackets and ports
	writer.Write(&ResultEvent{Host: "[::1]:8080", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "[::1]:9090", TemplateID: "t2"})

	// Should normalize to just ::1
	if !detector.IsHoneypot("::1") {
		t.Error("Should detect honeypot with IPv6 normalization")
	}
}

func TestHoneypotWriterHostWithPort(t *testing.T) {
	// Test that Host field with port is normalized
	mock := &mockWriter{}
	detector := honeypotdetector.New(2, 100)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false)

	// Host field with port
	writer.Write(&ResultEvent{Host: "example.com:443", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "example.com:8443", TemplateID: "t2"})

	// Should normalize ports away
	if !detector.IsHoneypot("example.com") {
		t.Error("Should detect honeypot with host:port normalization")
	}
}

func TestHoneypotWriterClose(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2, 100)

	writer := NewHoneypotWriter(mock, detector, false, false)

	// Create a honeypot
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t2"})

	writer.Close()

	if !mock.closed {
		t.Error("Underlying writer should be closed")
	}
}
