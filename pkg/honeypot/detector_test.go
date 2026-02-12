package honeypot

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectorBasic(t *testing.T) {
	d := New(3)
	require.True(t, d.IsEnabled())

	// Record matches below threshold
	require.False(t, d.RecordMatch("example.com", "template-1"))
	require.False(t, d.IsHoneypot("example.com"))
	require.Equal(t, 1, d.GetMatchCount("example.com"))

	require.False(t, d.RecordMatch("example.com", "template-2"))
	require.False(t, d.IsHoneypot("example.com"))
	require.Equal(t, 2, d.GetMatchCount("example.com"))

	// Third unique match triggers honeypot flag
	require.True(t, d.RecordMatch("example.com", "template-3"))
	require.True(t, d.IsHoneypot("example.com"))
	require.Equal(t, 3, d.GetMatchCount("example.com"))
	require.Equal(t, 1, d.FlaggedCount())
}

func TestDetectorDuplicateTemplates(t *testing.T) {
	d := New(3)

	// Same template multiple times should not inflate count
	d.RecordMatch("example.com", "template-1")
	d.RecordMatch("example.com", "template-1")
	d.RecordMatch("example.com", "template-1")
	require.Equal(t, 1, d.GetMatchCount("example.com"))
	require.False(t, d.IsHoneypot("example.com"))
}

func TestDetectorMultipleHosts(t *testing.T) {
	d := New(2)

	d.RecordMatch("host1.com", "t1")
	d.RecordMatch("host1.com", "t2")
	d.RecordMatch("host2.com", "t1")

	require.True(t, d.IsHoneypot("host1.com"))
	require.False(t, d.IsHoneypot("host2.com"))
	require.Equal(t, 1, d.FlaggedCount())
}

func TestDetectorDisabled(t *testing.T) {
	d := New(0)
	require.False(t, d.IsEnabled())
	require.False(t, d.RecordMatch("example.com", "t1"))
	require.False(t, d.IsHoneypot("example.com"))
	require.Equal(t, 0, d.GetMatchCount("example.com"))
}

func TestDetectorNegativeThreshold(t *testing.T) {
	d := New(-1)
	require.False(t, d.IsEnabled())
}

func TestDetectorRecordAfterFlagged(t *testing.T) {
	d := New(2)

	d.RecordMatch("example.com", "t1")
	d.RecordMatch("example.com", "t2") // flags
	require.True(t, d.IsHoneypot("example.com"))

	// Additional match after flagging should still be tracked
	require.False(t, d.RecordMatch("example.com", "t3")) // returns false (already flagged)
	require.Equal(t, 3, d.GetMatchCount("example.com"))
	require.Equal(t, 1, d.FlaggedCount()) // still 1
}

func TestDetectorFlaggedHosts(t *testing.T) {
	d := New(2)

	d.RecordMatch("host1.com", "t1")
	d.RecordMatch("host1.com", "t2")
	d.RecordMatch("host2.com", "t1")
	d.RecordMatch("host3.com", "t1")
	d.RecordMatch("host3.com", "t2")

	flagged := d.FlaggedHosts()
	require.Len(t, flagged, 2)
	require.Contains(t, flagged, "host1.com")
	require.Contains(t, flagged, "host3.com")
	require.Equal(t, 2, flagged["host1.com"])
	require.Equal(t, 2, flagged["host3.com"])
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/path", "example.com"},
		{"https://example.com:443/path?q=1", "example.com"},
		{"example.com:8080", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"http://[::1]:8080/path", "::1"},
		{"http://user:pass@example.com/path", "example.com"},
		{"http://user@example.com:8080", "example.com"},
		{"user:pass@example.com", "example.com"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHost(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectorHostNormalization(t *testing.T) {
	d := New(2)

	// Different representations of the same host should be tracked together
	d.RecordMatch("http://example.com/page1", "t1")
	d.RecordMatch("https://example.com:443/page2", "t2")
	require.True(t, d.IsHoneypot("example.com"))
	require.True(t, d.IsHoneypot("http://example.com"))
	require.True(t, d.IsHoneypot("https://EXAMPLE.COM:443"))
}

func TestDetectorEmptyHost(t *testing.T) {
	d := New(2)
	require.False(t, d.RecordMatch("", "t1"))
	require.False(t, d.RecordMatch("   ", "t1"))
	require.False(t, d.IsHoneypot(""))
	require.Equal(t, 0, d.GetMatchCount(""))
}

func TestDetectorConcurrentAccess(t *testing.T) {
	d := New(5)
	var wg sync.WaitGroup
	host := "concurrent-test.com"

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			d.RecordMatch(host, fmt.Sprintf("template-%d", n%10))
		}(i)
	}
	wg.Wait()

	// Should have exactly 10 unique templates (template-0 through template-9)
	require.Equal(t, 10, d.GetMatchCount(host))
	require.True(t, d.IsHoneypot(host))
	require.Equal(t, 1, d.FlaggedCount())
}

func TestDetectorConcurrentMultipleHosts(t *testing.T) {
	d := New(3)
	var wg sync.WaitGroup

	// Simulate scanning multiple hosts concurrently
	for h := 0; h < 20; h++ {
		for tmpl := 0; tmpl < 5; tmpl++ {
			wg.Add(1)
			go func(hostIdx, tmplIdx int) {
				defer wg.Done()
				host := fmt.Sprintf("host-%d.com", hostIdx)
				tmpl := fmt.Sprintf("template-%d", tmplIdx)
				d.RecordMatch(host, tmpl)
			}(h, tmpl)
		}
	}
	wg.Wait()

	// All 20 hosts should have 5 unique templates and be flagged (threshold=3)
	require.Equal(t, 20, d.FlaggedCount())
	for h := 0; h < 20; h++ {
		host := fmt.Sprintf("host-%d.com", h)
		require.True(t, d.IsHoneypot(host), "host %s should be flagged", host)
		require.Equal(t, 5, d.GetMatchCount(host))
	}
}

func TestDetectorUnknownHost(t *testing.T) {
	d := New(5)
	require.False(t, d.IsHoneypot("unknown.com"))
	require.Equal(t, 0, d.GetMatchCount("unknown.com"))
}
