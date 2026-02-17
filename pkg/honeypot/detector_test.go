package honeypot

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectorDisabledByDefault(t *testing.T) {
	d := New(0, false)
	require.False(t, d.Enabled())
	flagged, suppress := d.Record("host1", "template1")
	require.False(t, flagged)
	require.False(t, suppress)
}

func TestDetectorNilSafe(t *testing.T) {
	var d *Detector
	require.False(t, d.Enabled())
	require.False(t, d.IsFlagged("host1"))
	require.Nil(t, d.FlaggedHosts())
	require.Empty(t, d.Summary())
}

func TestDetectorThresholdTriggered(t *testing.T) {
	d := New(3, false)
	require.True(t, d.Enabled())

	// Below threshold
	flagged, _ := d.Record("host1", "cve-2021-001")
	require.False(t, flagged)
	flagged, _ = d.Record("host1", "cve-2021-002")
	require.False(t, flagged)

	// Hits threshold
	flagged, suppress := d.Record("host1", "cve-2021-003")
	require.True(t, flagged)
	require.False(t, suppress) // suppress is false in warn-only mode
}

func TestDetectorSuppressMode(t *testing.T) {
	d := New(2, true)

	d.Record("host1", "t1")
	flagged, suppress := d.Record("host1", "t2")
	require.True(t, flagged)
	require.True(t, suppress)

	// Subsequent records for flagged host should also suppress
	flagged, suppress = d.Record("host1", "t3")
	require.True(t, flagged)
	require.True(t, suppress)
}

func TestDetectorWarnOnlyMode(t *testing.T) {
	d := New(2, false)

	d.Record("host1", "t1")
	flagged, suppress := d.Record("host1", "t2")
	require.True(t, flagged)
	require.False(t, suppress) // warn only, never suppress
}

func TestDetectorDuplicateTemplateNotCounted(t *testing.T) {
	d := New(3, false)

	// Same template ID should not be counted multiple times
	d.Record("host1", "cve-2021-001")
	d.Record("host1", "cve-2021-001")
	d.Record("host1", "cve-2021-001")

	require.False(t, d.IsFlagged("host1"))
}

func TestDetectorMultipleHosts(t *testing.T) {
	d := New(2, true)

	// Host1 gets flagged
	d.Record("host1", "t1")
	d.Record("host1", "t2")
	require.True(t, d.IsFlagged("host1"))

	// Host2 should not be affected
	d.Record("host2", "t1")
	require.False(t, d.IsFlagged("host2"))
}

func TestDetectorEmptyInputs(t *testing.T) {
	d := New(2, false)
	flagged, _ := d.Record("", "t1")
	require.False(t, flagged)
	flagged, _ = d.Record("host1", "")
	require.False(t, flagged)
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"https://example.com:8443/path?q=1", "example.com:8443"},
		{"http://user:pass@example.com", "example.com"},
		{"example.com", "example.com"},
		{"example.com:8080", "example.com:8080"},
		{"example.com/path/to/resource", "example.com"},
		{"user:pass@example.com:22", "example.com:22"},
		{"", ""},
		{"  https://example.com  ", "example.com"},
		// IPv6 bracket notation (preserved to avoid ambiguity)
		{"https://[::1]:8080/path", "[::1]:8080"},
		{"[::1]:8080", "[::1]:8080"},
		{"[::1]", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHost(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestDetectorFlaggedHosts(t *testing.T) {
	d := New(2, false)

	d.Record("host1", "t1")
	d.Record("host1", "t2")
	d.Record("host2", "t1")
	d.Record("host2", "t2")

	flagged := d.FlaggedHosts()
	require.Len(t, flagged, 2)
	require.Equal(t, 2, flagged["host1"])
	require.Equal(t, 2, flagged["host2"])
}

func TestDetectorSummary(t *testing.T) {
	d := New(2, false)

	// No flagged hosts
	require.Empty(t, d.Summary())

	// Flag a host
	d.Record("host1", "t1")
	d.Record("host1", "t2")

	summary := d.Summary()
	require.Contains(t, summary, "1 host(s) flagged")
	require.Contains(t, summary, "host1")
}

func TestDetectorHostNormalization(t *testing.T) {
	d := New(2, false)

	// Different URL forms of same host should be normalized
	d.Record("https://example.com/path1", "t1")
	d.Record("https://example.com/path2", "t2")

	require.True(t, d.IsFlagged("example.com"))
}

func TestDetectorConcurrentAccess(t *testing.T) {
	d := New(10, false)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("host%d", i%5)
			templateID := fmt.Sprintf("template-%d", i)
			d.Record(host, templateID)
		}(i)
	}
	wg.Wait()

	// Should not panic and flagged hosts should be consistent
	flagged := d.FlaggedHosts()
	// All 5 hosts (host0-host4) should be flagged: 100 goroutines / 5 hosts = 20 templates each > threshold 10
	require.Len(t, flagged, 5)
	for _, count := range flagged {
		require.GreaterOrEqual(t, count, 10)
	}
}
