// Package output provides tests for the HoneypotWriter output wrapper.
// These tests verify host normalization, suppression logic, export format,
// concurrent write safety, integration workflows, and field propagation.
package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
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
	mu            sync.Mutex
}

func (m *mockWriter) Close()                   { m.closed = true }
func (m *mockWriter) Colorizer() aurora.Aurora { return aurora.NewAurora(false) }
func (m *mockWriter) Write(event *ResultEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, event)
	m.resultCounter++
	return nil
}
func (m *mockWriter) WriteFailure(event *InternalWrappedEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = append(m.failures, event)
	return nil
}
func (m *mockWriter) Request(templateID, url, requestType string, err error)       {}
func (m *mockWriter) RequestStatsLog(statusCode, response string)                  {}
func (m *mockWriter) WriteStoreDebugData(host, templateID, eventType, data string) {}
func (m *mockWriter) ResultCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resultCounter
}

var _ Writer = &mockWriter{}

func TestHoneypotWriterPassthrough(t *testing.T) {
	// Test that results pass through when under threshold
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

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
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

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
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "") // suppression ON

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
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "")

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
	writer := NewHoneypotWriter(mock, nil, false, false, "")

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
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

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
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "")

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
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

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
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

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
	detector := honeypotdetector.New(2)

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Create a honeypot
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t2"})

	writer.Close()

	if !mock.closed {
		t.Error("Underlying writer should be closed")
	}
}

func TestHoneypotWriterMatchCount(t *testing.T) {
	// Test that HoneypotMatchCount is set correctly in JSON output
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Write enough to trigger honeypot
	for i := 0; i < 5; i++ {
		event := &ResultEvent{
			Host:       "honeypot.com",
			TemplateID: "template-" + string(rune('a'+i)),
		}
		writer.Write(event)
	}

	// Check that the events after threshold have match count set
	for i, result := range mock.results {
		if i >= 2 { // After threshold (3), events should have count
			if !result.HoneypotHost {
				t.Errorf("Result %d should have HoneypotHost=true", i)
			}
			if result.HoneypotMatchCount == 0 {
				t.Errorf("Result %d should have HoneypotMatchCount > 0, got %d", i, result.HoneypotMatchCount)
			}
		}
	}
}

func TestHoneypotWriterExport(t *testing.T) {
	// Test honeypot export functionality
	tmpFile := t.TempDir() + "/honeypots.txt"
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)

	writer := NewHoneypotWriter(mock, detector, false, false, tmpFile)

	// Create honeypots
	writer.Write(&ResultEvent{Host: "honeypot1.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot1.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t3"})

	writer.Close()

	// Verify file was created and contains hosts with match counts
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	content := string(data)
	// Check for CSV format: host,count
	if !contains(content, "honeypot1.com,2") || !contains(content, "honeypot2.com,3") {
		t.Errorf("Export file should contain honeypot hosts with counts, got: %s", content)
	}
	// Check for header comments
	if !contains(content, "# Honeypot hosts") {
		t.Errorf("Export file should contain header comment, got: %s", content)
	}
}

func TestHoneypotWriterSuppressedCount(t *testing.T) {
	// Test that suppressed count is tracked correctly
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "")

	// Write enough to trigger and suppress
	for i := 0; i < 5; i++ {
		writer.Write(&ResultEvent{
			Host:       "honeypot.com",
			TemplateID: "template-" + string(rune('a'+i)),
		})
	}

	// Should have suppressed 3 results (after the 2nd which is the threshold-crossing one)
	if writer.GetSuppressedCount() != 3 {
		t.Errorf("Expected 3 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestHoneypotWriterVerboseMode(t *testing.T) {
	// Test that verbose mode doesn't cause errors
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, true, "") // verbose=true

	// Write enough to trigger honeypot
	writer.Write(&ResultEvent{Host: "verbose-test.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "verbose-test.com", TemplateID: "t2"})

	// Should still work without panicking
	if len(mock.results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(mock.results))
	}
}

func TestHoneypotWriterConcurrentWrites(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Concurrent writes should not cause race conditions
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				writer.Write(&ResultEvent{
					Host:       "concurrent.com",
					TemplateID: "template-" + string(rune('A'+id)) + "-" + string(rune('0'+j)),
				})
			}
		}(i)
	}
	wg.Wait()

	// Should have detected as honeypot
	if !detector.IsHoneypot("concurrent.com") {
		t.Error("Host should be flagged as honeypot after concurrent writes")
	}
}

func TestHoneypotWriterExportNoHoneypots(t *testing.T) {
	// Test export when no honeypots detected
	tmpFile := t.TempDir() + "/empty_export.txt"
	mock := &mockWriter{}
	detector := honeypotdetector.New(10) // High threshold

	writer := NewHoneypotWriter(mock, detector, false, false, tmpFile)

	// Write results under threshold
	writer.Write(&ResultEvent{Host: "clean.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "clean.com", TemplateID: "t2"})

	writer.Close()

	// File should not be created if no honeypots
	if _, err := os.Stat(tmpFile); err == nil {
		// File exists, check it's empty or has only headers
		data, _ := os.ReadFile(tmpFile)
		content := string(data)
		if contains(content, "clean.com") {
			t.Error("Export file should not contain non-honeypot hosts")
		}
	}
}

func TestHoneypotWriterResultCount(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Write some results
	writer.Write(&ResultEvent{Host: "host.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "host.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "host.com", TemplateID: "t3"})

	// ResultCount should delegate to underlying writer
	if writer.ResultCount() != 3 {
		t.Errorf("Expected ResultCount 3, got %d", writer.ResultCount())
	}
}

func TestHoneypotWriterGetDetector(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// GetDetector should return the same detector
	if writer.GetDetector() != detector {
		t.Error("GetDetector should return the original detector")
	}
}

func TestHoneypotWriterNormalizesURLVariations(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Different URL variations for the same host
	writer.Write(&ResultEvent{Host: "example.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "example.com:80", TemplateID: "t2"})
	writer.Write(&ResultEvent{URL: "https://example.com:443/path", TemplateID: "t3"})

	// Should all normalize to same host and trigger honeypot
	if !detector.IsHoneypot("example.com") {
		t.Error("URL variations should normalize to same host")
	}
}

// Test normalizeHost function directly via various scenarios
func TestNormalizeHostIPv4(t *testing.T) {
	tests := []struct {
		host     string
		urlField string
		expected string
	}{
		{"192.168.1.1", "", "192.168.1.1"},
		{"192.168.1.1:8080", "", "192.168.1.1"},
		{"", "http://10.0.0.1:80/path", "10.0.0.1"},
		{"", "https://172.16.0.1:443", "172.16.0.1"},
	}

	for _, tc := range tests {
		result := normalizeHost(tc.host, tc.urlField)
		if result != tc.expected {
			t.Errorf("normalizeHost(%q, %q) = %q, expected %q", tc.host, tc.urlField, result, tc.expected)
		}
	}
}

func TestNormalizeHostIPv6(t *testing.T) {
	tests := []struct {
		host     string
		urlField string
		expected string
	}{
		{"[::1]:8080", "", "::1"},
		{"::1", "", "::1"},
		{"[2001:db8::1]:443", "", "2001:db8::1"},
		{"", "http://[::1]:8080/path", "::1"},
	}

	for _, tc := range tests {
		result := normalizeHost(tc.host, tc.urlField)
		if result != tc.expected {
			t.Errorf("normalizeHost(%q, %q) = %q, expected %q", tc.host, tc.urlField, result, tc.expected)
		}
	}
}

func TestNormalizeHostDomains(t *testing.T) {
	tests := []struct {
		host     string
		urlField string
		expected string
	}{
		{"example.com", "", "example.com"},
		{"EXAMPLE.COM", "", "example.com"},
		{"Example.Com:8080", "", "example.com"},
		{"sub.domain.co.uk:443", "", "sub.domain.co.uk"},
		{"", "https://WWW.EXAMPLE.COM/path", "www.example.com"},
	}

	for _, tc := range tests {
		result := normalizeHost(tc.host, tc.urlField)
		if result != tc.expected {
			t.Errorf("normalizeHost(%q, %q) = %q, expected %q", tc.host, tc.urlField, result, tc.expected)
		}
	}
}

func TestNormalizeHostEdgeCases(t *testing.T) {
	tests := []struct {
		host     string
		urlField string
		expected string
	}{
		{"", "", ""},
		{"", "not-a-url", "not-a-url"},
		{"", "://invalid", "://invalid"},
		{"host-only", "", "host-only"},
	}

	for _, tc := range tests {
		result := normalizeHost(tc.host, tc.urlField)
		if result != tc.expected {
			t.Errorf("normalizeHost(%q, %q) = %q, expected %q", tc.host, tc.urlField, result, tc.expected)
		}
	}
}

func TestHoneypotWriterWriteFailure(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// WriteFailure should delegate to underlying writer
	event := &InternalWrappedEvent{}
	err := writer.WriteFailure(event)
	if err != nil {
		t.Errorf("WriteFailure failed: %v", err)
	}

	if len(mock.failures) != 1 {
		t.Errorf("Expected 1 failure, got %d", len(mock.failures))
	}
}

func TestHoneypotWriterColorizer(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Colorizer should return underlying writer's colorizer
	colorizer := writer.Colorizer()
	if colorizer == nil {
		t.Error("Colorizer should not be nil")
	}
}

func TestHoneypotWriterRequest(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Request should not panic (delegates to underlying writer)
	writer.Request("template-1", "http://example.com", "http", nil)
}

func TestHoneypotWriterRequestStatsLog(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// RequestStatsLog should not panic
	writer.RequestStatsLog("200", "OK")
}

func TestHoneypotWriterWriteStoreDebugData(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// WriteStoreDebugData should not panic
	writer.WriteStoreDebugData("host.com", "template-1", "http", "debug data")
}

func TestHoneypotWriterHoneypotHostFieldSet(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// First two writes should NOT have HoneypotHost set
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t1"})
	if mock.results[0].HoneypotHost {
		t.Error("First result should not have HoneypotHost=true")
	}

	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t2"})
	// Second write crosses threshold, should have HoneypotHost=true
	if !mock.results[1].HoneypotHost {
		t.Error("Threshold-crossing result should have HoneypotHost=true")
	}

	// Third write should also have HoneypotHost=true
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t3"})
	if !mock.results[2].HoneypotHost {
		t.Error("Post-threshold result should have HoneypotHost=true")
	}
}

func TestHoneypotWriterMatchCountFieldSet(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Write enough to trigger honeypot
	writer.Write(&ResultEvent{Host: "count.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "count.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "count.com", TemplateID: "t3"})

	// Check match counts are set correctly
	if mock.results[1].HoneypotMatchCount != 2 {
		t.Errorf("Expected HoneypotMatchCount=2, got %d", mock.results[1].HoneypotMatchCount)
	}
	if mock.results[2].HoneypotMatchCount != 3 {
		t.Errorf("Expected HoneypotMatchCount=3, got %d", mock.results[2].HoneypotMatchCount)
	}
}

func TestHoneypotWriterSuppressionOnlyAfterThreshold(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "") // suppress=true

	// First write: passes through
	writer.Write(&ResultEvent{Host: "suppress.com", TemplateID: "t1"})
	// Second write: threshold-crossing, passes through with warning
	writer.Write(&ResultEvent{Host: "suppress.com", TemplateID: "t2"})
	// Third write: suppressed
	writer.Write(&ResultEvent{Host: "suppress.com", TemplateID: "t3"})
	// Fourth write: suppressed
	writer.Write(&ResultEvent{Host: "suppress.com", TemplateID: "t4"})

	// Should have 2 results (t1 and t2), not 4
	if len(mock.results) != 2 {
		t.Errorf("Expected 2 results (threshold-crossing passes), got %d", len(mock.results))
	}

	// Should have 2 suppressed
	if writer.GetSuppressedCount() != 2 {
		t.Errorf("Expected 2 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterMultipleHostsSuppression(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "")

	// Host A becomes honeypot
	writer.Write(&ResultEvent{Host: "hostA.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "hostA.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "hostA.com", TemplateID: "t3"}) // suppressed

	// Host B becomes honeypot
	writer.Write(&ResultEvent{Host: "hostB.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "hostB.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "hostB.com", TemplateID: "t3"}) // suppressed

	// Host C stays clean
	writer.Write(&ResultEvent{Host: "hostC.com", TemplateID: "t1"})

	// 2 from A + 2 from B + 1 from C = 5
	if len(mock.results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(mock.results))
	}

	// 2 suppressed (1 from A, 1 from B)
	if writer.GetSuppressedCount() != 2 {
		t.Errorf("Expected 2 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterEmptyEventFields(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Event with empty host and URL should still be written
	writer.Write(&ResultEvent{TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "", URL: "", TemplateID: "t2"})

	if len(mock.results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(mock.results))
	}
}

func TestHoneypotWriterExportCSVFormat(t *testing.T) {
	tmpFile := t.TempDir() + "/csv_test.txt"
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)

	writer := NewHoneypotWriter(mock, detector, false, false, tmpFile)

	// Create honeypot with 5 templates
	for i := 0; i < 5; i++ {
		writer.Write(&ResultEvent{Host: "csv-test.com", TemplateID: "template-" + string(rune('A'+i))})
	}

	writer.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	content := string(data)

	// Check header
	if !strings.Contains(content, "# Honeypot hosts") {
		t.Error("Export should contain header comment")
	}
	if !strings.Contains(content, "# Format: host,match_count") {
		t.Error("Export should contain format specification")
	}

	// Check CSV format: host,count
	if !strings.Contains(content, "csv-test.com,5") {
		t.Errorf("Export should contain 'csv-test.com,5', got: %s", content)
	}
}

func TestHoneypotWriterCloseWithDetector(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Create a honeypot
	writer.Write(&ResultEvent{Host: "close-test.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "close-test.com", TemplateID: "t2"})

	// Close should not panic and should close underlying writer
	writer.Close()

	if !mock.closed {
		t.Error("Close should close underlying writer")
	}
}

func TestHoneypotWriterCloseWithNilDetector(t *testing.T) {
	mock := &mockWriter{}

	writer := NewHoneypotWriter(mock, nil, false, false, "")

	// Close with nil detector should not panic
	writer.Close()

	if !mock.closed {
		t.Error("Close should close underlying writer even with nil detector")
	}
}

// Integration tests verifying full workflow
func TestHoneypotWriterIntegrationFullWorkflow(t *testing.T) {
	tmpFile := t.TempDir() + "/full_workflow.txt"
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)

	writer := NewHoneypotWriter(mock, detector, true, false, tmpFile)

	// Stage 1: Clean hosts
	writer.Write(&ResultEvent{Host: "clean1.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "clean2.com", TemplateID: "t1"})

	// Stage 2: Honeypot develops
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t3"}) // Flagged

	// Stage 3: Suppressed results
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t4"}) // Suppressed
	writer.Write(&ResultEvent{Host: "honeypot.com", TemplateID: "t5"}) // Suppressed

	// Stage 4: Another honeypot
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t3"})
	writer.Write(&ResultEvent{Host: "honeypot2.com", TemplateID: "t4"}) // Suppressed

	writer.Close()

	// Verify results: 2 clean + 3 honeypot1 + 3 honeypot2 = 8
	if len(mock.results) != 8 {
		t.Errorf("Expected 8 results, got %d", len(mock.results))
	}

	// Verify suppression: 3 suppressed
	if writer.GetSuppressedCount() != 3 {
		t.Errorf("Expected 3 suppressed, got %d", writer.GetSuppressedCount())
	}

	// Verify export file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export: %v", err)
	}
	content := string(data)
	if !contains(content, "honeypot.com") || !contains(content, "honeypot2.com") {
		t.Error("Export should contain both honeypots")
	}
}

func TestHoneypotWriterIntegrationWithBlocklist(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/blocklist.txt"
	exportPath := tmpDir + "/export.txt"

	// Create blocklist
	os.WriteFile(blocklistPath, []byte("known-bad.com\n"), 0644)

	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	detector.LoadBlocklist(blocklistPath)

	writer := NewHoneypotWriter(mock, detector, true, false, exportPath)

	// Pre-blocked host: immediately flagged, ALL writes suppressed
	writer.Write(&ResultEvent{Host: "known-bad.com", TemplateID: "t1"}) // Suppressed
	writer.Write(&ResultEvent{Host: "known-bad.com", TemplateID: "t2"}) // Suppressed

	// New host: not pre-blocked, passes through
	writer.Write(&ResultEvent{Host: "new-host.com", TemplateID: "t1"})

	writer.Close()

	// Should have 1 result (only new-host passes)
	if len(mock.results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(mock.results))
	}
	// 2 suppressed (both writes to known-bad)
	if writer.GetSuppressedCount() != 2 {
		t.Errorf("Expected 2 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterThresholdOfTwo(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// First write: not flagged
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t1"})
	if mock.results[0].HoneypotHost {
		t.Error("First write should not be flagged")
	}

	// Second write: flagged (threshold reached)
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t2"})
	if !mock.results[1].HoneypotHost {
		t.Error("Second write should be flagged")
	}
	if mock.results[1].HoneypotMatchCount != 2 {
		t.Errorf("Expected match count 2, got %d", mock.results[1].HoneypotMatchCount)
	}
}

func TestHoneypotWriterDifferentProtocols(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Same host, different URL schemes
	writer.Write(&ResultEvent{URL: "http://example.com/path1", TemplateID: "t1"})
	writer.Write(&ResultEvent{URL: "https://example.com/path2", TemplateID: "t2"})
	writer.Write(&ResultEvent{URL: "http://example.com:8080/path3", TemplateID: "t3"})

	// Should normalize to same host
	if !detector.IsHoneypot("example.com") {
		t.Error("All protocols should normalize to same host")
	}
}

func TestHoneypotWriterMixedHostAndURL(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Mix of Host and URL fields
	writer.Write(&ResultEvent{Host: "mixed.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{URL: "https://mixed.com/path", TemplateID: "t2"})
	writer.Write(&ResultEvent{Host: "mixed.com:443", TemplateID: "t3"})

	if !detector.IsHoneypot("mixed.com") {
		t.Error("Mixed Host/URL should normalize correctly")
	}
}

func TestHoneypotWriterExportMultipleHoneypots(t *testing.T) {
	tmpFile := t.TempDir() + "/multi_export.txt"
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, tmpFile)

	// Create 5 honeypots (hosts are normalized to lowercase)
	hosts := []string{"honeypot1.com", "honeypot2.com", "honeypot3.com", "honeypot4.com", "honeypot5.com"}
	for _, host := range hosts {
		writer.Write(&ResultEvent{Host: host, TemplateID: "t1"})
		writer.Write(&ResultEvent{Host: host, TemplateID: "t2"})
	}

	writer.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}
	content := string(data)

	// All 5 should be in export
	for _, host := range hosts {
		if !contains(content, host) {
			t.Errorf("Export should contain %s", host)
		}
	}
}

func TestHoneypotWriterSuppressDisabled(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "") // suppress=false

	// All writes should pass through
	for i := 0; i < 10; i++ {
		writer.Write(&ResultEvent{Host: "all-pass.com", TemplateID: "t" + string(rune('0'+i))})
	}

	if len(mock.results) != 10 {
		t.Errorf("Expected 10 results with suppress=false, got %d", len(mock.results))
	}
	if writer.GetSuppressedCount() != 0 {
		t.Errorf("Expected 0 suppressed with suppress=false, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterSuppressEnabled(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "") // suppress=true

	// Write 10 templates
	for i := 0; i < 10; i++ {
		writer.Write(&ResultEvent{Host: "suppress.com", TemplateID: "t" + string(rune('A'+i))})
	}

	// First 2 pass, remaining 8 suppressed
	if len(mock.results) != 2 {
		t.Errorf("Expected 2 results with suppress=true, got %d", len(mock.results))
	}
	if writer.GetSuppressedCount() != 8 {
		t.Errorf("Expected 8 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterIPv6Address(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	writer.Write(&ResultEvent{Host: "[2001:db8::1]:8080", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "[2001:db8::1]:443", TemplateID: "t2"})

	// Should normalize to same IPv6
	if !detector.IsHoneypot("2001:db8::1") {
		t.Error("IPv6 addresses should normalize correctly")
	}
}

func TestHoneypotWriterIPv4Address(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	writer.Write(&ResultEvent{Host: "192.168.1.1:80", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "192.168.1.1:443", TemplateID: "t2"})

	if !detector.IsHoneypot("192.168.1.1") {
		t.Error("IPv4 addresses should normalize correctly")
	}
}

func TestHoneypotWriterSubdomainHandling(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Different subdomains are different hosts
	writer.Write(&ResultEvent{Host: "www.example.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "api.example.com", TemplateID: "t1"})

	// Neither should be flagged (only 1 template each)
	if detector.IsHoneypot("www.example.com") || detector.IsHoneypot("api.example.com") {
		t.Error("Different subdomains should be tracked separately")
	}
}

func TestHoneypotWriterLargeScaleHoneypots(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(5)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, true, false, "")

	// Create 100 honeypots with proper hostnames
	for i := 0; i < 100; i++ {
		host := fmt.Sprintf("honeypot%d.com", i)
		for j := 0; j < 10; j++ {
			writer.Write(&ResultEvent{Host: host, TemplateID: fmt.Sprintf("template-%d", j)})
		}
	}

	if detector.GetHoneypotCount() != 100 {
		t.Errorf("Expected 100 honeypots, got %d", detector.GetHoneypotCount())
	}

	// 5 pass per host, 5 suppressed per host = 500 suppressed
	if writer.GetSuppressedCount() != 500 {
		t.Errorf("Expected 500 suppressed, got %d", writer.GetSuppressedCount())
	}
}

func TestHoneypotWriterExportPathEmpty(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)

	writer := NewHoneypotWriter(mock, detector, false, false, "") // empty export path

	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t2"})

	// Should not panic when closing with empty export path
	writer.Close()
}

func TestHoneypotWriterExportPathInvalid(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)

	// Invalid path (directory doesn't exist)
	writer := NewHoneypotWriter(mock, detector, false, false, "/nonexistent/path/export.txt")

	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t1"})
	writer.Write(&ResultEvent{Host: "test.com", TemplateID: "t2"})

	// Should not panic, just log error
	writer.Close()
}

func TestHoneypotWriterDuplicateTemplatesSameHost(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(3)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Same template multiple times
	writer.Write(&ResultEvent{Host: "dupe.com", TemplateID: "same-template"})
	writer.Write(&ResultEvent{Host: "dupe.com", TemplateID: "same-template"})
	writer.Write(&ResultEvent{Host: "dupe.com", TemplateID: "same-template"})

	// Should not be flagged (only 1 unique template)
	if detector.IsHoneypot("dupe.com") {
		t.Error("Duplicate templates should not count multiple times")
	}
	if detector.GetMatchCount("dupe.com") != 1 {
		t.Errorf("Expected match count 1, got %d", detector.GetMatchCount("dupe.com"))
	}
}

func TestHoneypotWriterResultEventPreserved(t *testing.T) {
	mock := &mockWriter{}
	detector := honeypotdetector.New(2)
	defer detector.Close()

	writer := NewHoneypotWriter(mock, detector, false, false, "")

	// Write with event that has various fields
	event := &ResultEvent{
		Host:             "preserve.com",
		TemplateID:       "test-template",
		Matched:          "matched content",
		ExtractedResults: []string{"result1", "result2"},
	}
	writer.Write(event)
	writer.Write(&ResultEvent{Host: "preserve.com", TemplateID: "t2"})

	// Original fields should be preserved
	if mock.results[0].Matched != "matched content" {
		t.Error("Matched content should be preserved")
	}
	if len(mock.results[0].ExtractedResults) != 2 {
		t.Error("ExtractedResults should be preserved")
	}
}
