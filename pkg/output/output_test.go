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
	tracker := NewHoneypotTracker(3)
	
	// Test capacity 3 by temporarily modifying the constant
	// We'll test with 4 hosts to trigger eviction
	hosts := []string{"host1", "host2", "host3", "host4"}
	templateID := "template1"
	
	// Add 3 hosts (should not trigger eviction)
	for i := 0; i < 3; i++ {
		isHoneypot, isFirstTime := tracker.AddSession(hosts[i], templateID)
		if isHoneypot || isFirstTime {
			t.Errorf("Expected no honeypot detection for new host %s", hosts[i])
		}
	}
	
	// Verify all 3 hosts are tracked
	stats, _, _ := tracker.GetStats()
	if stats != 3 {
		t.Errorf("Expected 3 hosts tracked, got %d", stats)
	}
	
	// Add 4th host (should trigger eviction of oldest)
	isHoneypot, isFirstTime := tracker.AddSession("host4", templateID)
	if isHoneypot || isFirstTime {
		t.Errorf("Expected no honeypot detection for new host host4")
	}
	
	// Verify capacity is maintained (still 3 hosts)
	stats, _, _ = tracker.GetStats()
	if stats != 3 {
		t.Errorf("Expected 3 hosts tracked after eviction, got %d", stats)
	}
	
	// Verify oldest host (host1) was evicted
	_, exists := tracker.GetSession("host1")
	if exists {
		t.Error("Expected host1 to be evicted")
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
