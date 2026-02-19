package honeypot

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDetectorDisabledByDefault verifies that a Detector with threshold 0 is inactive
// and never flags or suppresses hosts.
func TestDetectorDisabledByDefault(t *testing.T) {
	d := New(0, false)
	require.False(t, d.Enabled())
	flagged, suppress := d.Record("host1", "template1")
	require.False(t, flagged)
	require.False(t, suppress)
}

// TestDetectorNilSafe verifies that all Detector methods are safe to call on a nil receiver
// without panicking, returning zero-value results.
func TestDetectorNilSafe(t *testing.T) {
	var d *Detector
	require.False(t, d.Enabled())
	flagged, suppress := d.Record("host1", "t1")
	require.False(t, flagged)
	require.False(t, suppress)
	require.False(t, d.IsFlagged("host1"))
	require.Nil(t, d.FlaggedHosts())
	require.Empty(t, d.Summary())
}

// TestDetectorThresholdTriggered verifies that a host is flagged once its unique template
// match count reaches the configured threshold.
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

// TestDetectorSuppressMode verifies that when suppress mode is enabled, results from
// flagged hosts return shouldSuppress=true on both the triggering and subsequent calls.
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

// TestDetectorWarnOnlyMode verifies that when suppress is disabled, flagged hosts return
// shouldSuppress=false so results are emitted with a warning rather than dropped.
func TestDetectorWarnOnlyMode(t *testing.T) {
	d := New(2, false)

	d.Record("host1", "t1")
	flagged, suppress := d.Record("host1", "t2")
	require.True(t, flagged)
	require.False(t, suppress) // warn only, never suppress
}

// TestDetectorDuplicateTemplateNotCounted verifies that repeated matches of the same
// template ID against a host are deduplicated and do not inflate the match count.
func TestDetectorDuplicateTemplateNotCounted(t *testing.T) {
	d := New(3, false)

	// Same template ID should not be counted multiple times
	d.Record("host1", "cve-2021-001")
	d.Record("host1", "cve-2021-001")
	d.Record("host1", "cve-2021-001")

	require.False(t, d.IsFlagged("host1"))
}

// TestDetectorMultipleHosts verifies that match tracking is isolated per host,
// so flagging one host does not affect the state of another.
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

// TestDetectorEmptyInputs verifies that Record gracefully handles empty host or
// template ID arguments without recording entries or panicking.
func TestDetectorEmptyInputs(t *testing.T) {
	d := New(2, false)
	flagged, _ := d.Record("", "t1")
	require.False(t, flagged)
	flagged, _ = d.Record("host1", "")
	require.False(t, flagged)
}

// TestDetectorEmptyHostURLs verifies that URLs with syntactically empty hosts
// (e.g. "http://", "://") are rejected by Record and do not create phantom entries.
func TestDetectorEmptyHostURLs(t *testing.T) {
	d := New(2, false)

	// URLs that are syntactically valid but have empty hosts should not
	// accumulate under a phantom "" key in the matches map.
	emptyHostInputs := []string{
		"http://",
		"http:///path",
		"https://",
		"://",
	}
	for _, input := range emptyHostInputs {
		flagged, suppress := d.Record(input, "t1")
		require.False(t, flagged, "expected no flag for empty-host URL: %q", input)
		require.False(t, suppress, "expected no suppress for empty-host URL: %q", input)
	}

	// Verify no phantom entries were created
	d.mu.RLock()
	_, hasEmpty := d.matches[""]
	d.mu.RUnlock()
	require.False(t, hasEmpty, "matches map should not contain an empty-string key")
}

// TestNormalizeHost exercises the normalizeHost helper with a table of URL formats,
// IPv4/IPv6 addresses, userinfo, trailing colons, and edge cases.
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
		{"http://[::1]", "[::1]"},
		{"[::1]:8080", "[::1]:8080"},
		{"[::1]", "[::1]"},
		// Bare IPv6 without brackets (wrapped for consistency)
		{"::1", "[::1]"},
		{"fe80::1", "[fe80::1]"},
		{"2001:db8::1", "[2001:db8::1]"},
		// Empty-host URLs — normalizeHost must return "" so Record() can reject them
		{"http://", ""},
		{"http:///path", ""},
		{"https://", ""},
		{"://", ""},
		// Trailing-colon inputs (host with no port) normalise to host without colon
		{"host:", "host"},
		{"example.com:", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHost(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestDetectorFlaggedHosts verifies that FlaggedHosts returns a snapshot of all
// flagged hosts with their match counts at the time of flagging.
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

// TestDetectorSummary verifies that Summary returns an empty string when no hosts
// are flagged, and a formatted report listing flagged hosts when present.
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

// TestDetectorHostNormalization verifies that different URL representations of the
// same host are normalized to a single key, so their matches are counted together.
func TestDetectorHostNormalization(t *testing.T) {
	d := New(2, false)

	// Different URL forms of same host should be normalized
	d.Record("https://example.com/path1", "t1")
	d.Record("https://example.com/path2", "t2")

	require.True(t, d.IsFlagged("example.com"))
}

// TestDetectorConcurrentAccess verifies that Record is safe for concurrent use from
// multiple goroutines, producing deterministic flag counts under contention.
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
		// Due to mutex serialisation, the flag fires exactly at threshold (10 unique templates)
		require.Equal(t, count, 10)
	}
}
