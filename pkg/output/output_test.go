package output

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHoneypotTracker_LRUEviction(t *testing.T) {
	// Create tracker with small capacity for testing
	tracker := NewHoneypotTracker()
	
	// Test capacity 3 by temporarily modifying the constant
	// We'll test with 4 hosts to trigger eviction
	hosts := []string{"host1", "host2", "host3", "host4"}
	templateID := "template1"
	
	// Add 3 hosts (should not trigger eviction)
	for i := 0; i < 3; i++ {
		isHoneypot, isFirstTime := tracker.AddAndCheck(hosts[i], templateID)
		if isHoneypot || isFirstTime {
			t.Errorf("Expected no honeypot detection for new host %s", hosts[i])
		}
	}
	
	// Verify all 3 hosts are tracked
	if len(tracker.hostTemplates) != 3 {
		t.Errorf("Expected 3 hosts tracked, got %d", len(tracker.hostTemplates))
	}
	
	// Verify order is correct (oldest to newest)
	expectedOrder := []string{"host1", "host2", "host3"}
	if len(tracker.order) != 3 {
		t.Errorf("Expected order length 3, got %d", len(tracker.order))
	} else {
		for i, host := range expectedOrder {
			if tracker.order[i] != host {
				t.Errorf("Expected order[%d] = %s, got %s", i, host, tracker.order[i])
			}
		}
	}
	
	// Add 4th host (should trigger eviction of oldest)
	isHoneypot, isFirstTime := tracker.AddAndCheck("host4", templateID)
	if isHoneypot || isFirstTime {
		t.Errorf("Expected no honeypot detection for new host host4")
	}
	
	// Verify capacity is maintained (still 3 hosts)
	if len(tracker.hostTemplates) != 3 {
		t.Errorf("Expected 3 hosts tracked after eviction, got %d", len(tracker.hostTemplates))
	}
	
	// Verify oldest host (host1) was evicted
	if _, exists := tracker.hostTemplates["host1"]; exists {
		t.Error("Expected host1 to be evicted from hostTemplates")
	}
	
	// Verify new order (host2, host3, host4)
	expectedOrder = []string{"host2", "host3", "host4"}
	if len(tracker.order) != 3 {
		t.Errorf("Expected order length 3 after eviction, got %d", len(tracker.order))
	} else {
		for i, host := range expectedOrder {
			if tracker.order[i] != host {
				t.Errorf("Expected order[%d] = %s after eviction, got %s", i, host, tracker.order[i])
			}
		}
	}
}

func TestHoneypotTracker_MRUAccess(t *testing.T) {
	tracker := NewHoneypotTracker()
	
	// Add 3 hosts
	hosts := []string{"host1", "host2", "host3"}
	templateID := "template1"
	
	for _, host := range hosts {
		tracker.AddAndCheck(host, templateID)
	}
	
	// Verify initial order
	expectedOrder := []string{"host1", "host2", "host3"}
	for i, host := range expectedOrder {
		if tracker.order[i] != host {
			t.Errorf("Initial order[%d] = %s, got %s", i, host, tracker.order[i])
		}
	}
	
	// Access host2 (should make it most recently used)
	tracker.AddAndCheck("host2", "template2")
	
	// Verify new order: host1, host3, host2
	expectedOrder = []string{"host1", "host3", "host2"}
	if len(tracker.order) != 3 {
		t.Errorf("Expected order length 3, got %d", len(tracker.order))
	} else {
		for i, host := range expectedOrder {
			if tracker.order[i] != host {
				t.Errorf("After accessing host2, order[%d] = %s, got %s", i, host, tracker.order[i])
			}
		}
	}
	
	// Access host1 (should make it most recently used)
	tracker.AddAndCheck("host1", "template3")
	
	// Verify new order: host3, host2, host1
	expectedOrder = []string{"host3", "host2", "host1"}
	for i, host := range expectedOrder {
		if tracker.order[i] != host {
			t.Errorf("After accessing host1, order[%d] = %s, got %s", i, host, tracker.order[i])
		}
	}
}

func TestHoneypotTracker_NewHosts(t *testing.T) {
	tracker := NewHoneypotTracker()
	
	// Test adding new hosts
	hosts := []string{"host1", "host2", "host3"}
	templateID := "template1"
	
	for i, host := range hosts {
		isHoneypot, isFirstTime := tracker.AddAndCheck(host, templateID)
		
		// Should not be honeypot with only 1 template
		if isHoneypot {
			t.Errorf("Host %s should not be honeypot with 1 template", host)
		}
		
		// Should not be first time honeypot detection
		if isFirstTime {
			t.Errorf("Host %s should not trigger first-time honeypot warning", host)
		}
		
		// Verify host is tracked
		if _, exists := tracker.hostTemplates[host]; !exists {
			t.Errorf("Host %s should be tracked", host)
		}
		
		// Verify template is tracked for host
		if len(tracker.hostTemplates[host]) != 1 {
			t.Errorf("Host %s should have 1 template, got %d", host, len(tracker.hostTemplates[host]))
		}
		
		// Verify order length
		if len(tracker.order) != i+1 {
			t.Errorf("Expected order length %d, got %d", i+1, len(tracker.order))
		}
		
		// Verify host is at end of order (most recent)
		if tracker.order[len(tracker.order)-1] != host {
			t.Errorf("Host %s should be at end of order", host)
		}
	}
}

func TestHoneypotTracker_HoneypotDetection(t *testing.T) {
	tracker := NewHoneypotTracker()
	host := "test-host"
	
	// Add templates until honeypot threshold (10+ templates)
	for i := 0; i < 15; i++ {
		templateID := fmt.Sprintf("template%c", 'A'+i)
		isHoneypot, isFirstTime := tracker.AddAndCheck(host, templateID)
		
		if i < 10 {
			// Should not be honeypot before threshold
			if isHoneypot {
				t.Errorf("Host should not be honeypot with %d templates", i+1)
			}
			if isFirstTime {
				t.Error("Should not trigger first-time honeypot warning before threshold")
			}
		} else if i == 10 {
			// Should become honeypot at threshold
			if !isHoneypot {
				t.Error("Host should be detected as honeypot at threshold")
			}
			if !isFirstTime {
				t.Error("Should trigger first-time honeypot warning at threshold")
			}
		} else {
			// Should remain honeypot but not first-time warning
			if !isHoneypot {
				t.Error("Host should remain honeypot after threshold")
			}
			if isFirstTime {
				t.Error("Should not trigger first-time honeypot warning after first detection")
			}
		}
	}
	
	// Verify host is in warned hosts list
	if _, warned := tracker.warnedHosts[host]; !warned {
		t.Error("Host should be in warned hosts list")
	}
}

func TestHoneypotTracker_InvalidHosts(t *testing.T) {
	tracker := NewHoneypotTracker()
	
	// Test invalid URLs (should return false, false)
	invalidHosts := []string{
		"http://[invalid-ipv6",
		"ftp://example.com",
		"",
		"not-a-url",
	}
	
	for _, host := range invalidHosts {
		isHoneypot, isFirstTime := tracker.AddAndCheck(host, "template1")
		if isHoneypot || isFirstTime {
			t.Errorf("Invalid host %s should return false, false", host)
		}
	}
	
	// Verify no hosts were tracked
	if len(tracker.hostTemplates) != 0 {
		t.Errorf("Expected no hosts tracked with invalid inputs, got %d", len(tracker.hostTemplates))
	}
}

func TestHoneypotTracker_URLParsing(t *testing.T) {
	tracker := NewHoneypotTracker()
	
	// Test various URL formats
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com:8080", "example.com"},
		{"example.com/path", "example.com"},
		{"http://example.com/path?query=1", "example.com"},
	}
	
	for _, tc := range testCases {
		isHoneypot, isFirstTime := tracker.AddAndCheck(tc.input, "template1")
		
		if isHoneypot || isFirstTime {
			t.Errorf("Valid host %s should not trigger honeypot on first access", tc.input)
		}
		
		// Verify host was tracked with correct hostname
		if _, exists := tracker.hostTemplates[tc.expected]; !exists {
			t.Errorf("Host %s should be tracked as %s", tc.input, tc.expected)
		}
	}
}

func TestStandardWriterRequest(t *testing.T) {
	t.Run("WithoutTraceAndError", func(t *testing.T) {
		w, err := NewStandardWriter(&types.Options{})
		require.NoError(t, err)
		require.NotPanics(t, func() {
			w.Request("path", "input", "http", nil)
			w.Close()
		})
	})

	t.Run("TraceAndErrorWithoutError", func(t *testing.T) {
		traceWriter := &testWriteCloser{}
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.traceFile = traceWriter
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request("path", "input", "http", nil)

		require.Equal(t, `{"template":"path","type":"http","input":"input","address":"input:","error":"none"}`, traceWriter.String())
		require.Empty(t, errorWriter.String())
	})

	t.Run("ErrorWithWrappedError", func(t *testing.T) {
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request(
			"misconfiguration/tcpconfig.yaml",
			"https://example.com/tcpconfig.html",
			"http",
			fmt.Errorf("GET https://example.com/tcpconfig.html/tcpconfig.html giving up after 2 attempts: %w", errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")),
		)

		require.Equal(t, `{"template":"misconfiguration/tcpconfig.yaml","type":"http","input":"https://example.com/tcpconfig.html","address":"example.com:443","error":"cause=\"context deadline exceeded (Client.Timeout exceeded while awaiting headers)\"","kind":"unknown-error"}`, errorWriter.String())
	})
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
