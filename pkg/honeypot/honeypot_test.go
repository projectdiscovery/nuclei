package honeypot

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"URL with scheme", "https://example.com/path?q=1", "example.com"},
		{"URL with port", "http://example.com:8080/admin", "example.com"},
		{"Host:port", "example.com:443", "example.com"},
		{"Bare host", "example.com", "example.com"},
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1"},
		{"IPv6 with brackets and port", "[::1]:8080", "::1"},
		{"IPv6 URL", "http://[2001:db8::1]:443/path", "2001:db8::1"},
		{"Empty string", "", ""},
		{"Whitespace", "  ", ""},
		{"Mixed case", "HTTP://Example.COM:8080", "example.com"},
		{"Trailing slash", "https://example.com/", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeHost(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectorDisabled(t *testing.T) {
	d := New(0, false)
	assert.False(t, d.IsEnabled(), "detector should be disabled with threshold 0")
	assert.False(t, d.RecordMatch("example.com", "cve-2021-1234"))
	assert.False(t, d.IsFlagged("example.com"))
	assert.False(t, d.ShouldSuppress("example.com"))
	assert.Equal(t, 0, d.MatchCount("example.com"))
	assert.Empty(t, d.FlaggedHosts())
}

func TestDetectorNegativeThreshold(t *testing.T) {
	d := New(-1, false)
	assert.False(t, d.IsEnabled())
}

func TestDetectorThresholdFlagging(t *testing.T) {
	d := New(3, false)
	require.True(t, d.IsEnabled())

	// Add 2 unique templates - should NOT be flagged yet
	assert.False(t, d.RecordMatch("example.com", "cve-2021-0001"))
	assert.False(t, d.RecordMatch("example.com", "cve-2021-0002"))
	assert.False(t, d.IsFlagged("example.com"))
	assert.Equal(t, 2, d.MatchCount("example.com"))

	// Add same template again - dedup, should NOT increase count
	assert.False(t, d.RecordMatch("example.com", "cve-2021-0002"))
	assert.Equal(t, 2, d.MatchCount("example.com"))
	assert.False(t, d.IsFlagged("example.com"))

	// Add 3rd unique template - should NOW be flagged
	assert.True(t, d.RecordMatch("example.com", "cve-2021-0003"))
	assert.True(t, d.IsFlagged("example.com"))

	// Subsequent record should return false (already flagged)
	assert.False(t, d.RecordMatch("example.com", "cve-2021-0004"))
}

func TestDetectorSuppression(t *testing.T) {
	// suppress=false: should not suppress even if flagged
	d := New(2, false)
	d.RecordMatch("target.com", "tmpl-1")
	d.RecordMatch("target.com", "tmpl-2")
	assert.True(t, d.IsFlagged("target.com"))
	assert.False(t, d.ShouldSuppress("target.com"))

	// suppress=true: should suppress flagged hosts
	d2 := New(2, true)
	d2.RecordMatch("target.com", "tmpl-1")
	d2.RecordMatch("target.com", "tmpl-2")
	assert.True(t, d2.IsFlagged("target.com"))
	assert.True(t, d2.ShouldSuppress("target.com"))

	// Non-flagged host should not be suppressed
	assert.False(t, d2.ShouldSuppress("clean.com"))
}

func TestDetectorHostNormalizationConsistency(t *testing.T) {
	d := New(2, false)

	// These should all map to the same host
	d.RecordMatch("https://example.com/path1", "tmpl-1")
	d.RecordMatch("http://example.com:8080/path2", "tmpl-2")

	// Should be flagged via any form of the host
	assert.True(t, d.IsFlagged("example.com"))
	assert.True(t, d.IsFlagged("https://example.com"))
	assert.True(t, d.IsFlagged("example.com:443"))
}

func TestDetectorMultipleHosts(t *testing.T) {
	d := New(2, false)

	// host1 gets 2 templates
	d.RecordMatch("host1.com", "tmpl-1")
	d.RecordMatch("host1.com", "tmpl-2")
	// host2 gets only 1 template
	d.RecordMatch("host2.com", "tmpl-1")

	assert.True(t, d.IsFlagged("host1.com"))
	assert.False(t, d.IsFlagged("host2.com"))

	flagged := d.FlaggedHosts()
	assert.Len(t, flagged, 1)
	assert.Contains(t, flagged, "host1.com")
}

func TestDetectorWarnOnce(t *testing.T) {
	d := New(2, false)
	d.RecordMatch("target.com", "tmpl-1")
	d.RecordMatch("target.com", "tmpl-2")

	// First warn should emit
	assert.True(t, d.WarnOnce("target.com"))
	// Second warn should be suppressed
	assert.False(t, d.WarnOnce("target.com"))
}

func TestDetectorConcurrency(t *testing.T) {
	d := New(50, false)
	var wg sync.WaitGroup

	// Launch many goroutines recording matches concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			host := "concurrent-host.com"
			tmplID := fmt.Sprintf("tmpl-%d", id)
			d.RecordMatch(host, tmplID)
		}(i)
	}
	wg.Wait()

	// With 100 unique templates and threshold 50, host should be flagged
	assert.True(t, d.IsFlagged("concurrent-host.com"))
}

func TestDetectorMemoryCleanup(t *testing.T) {
	d := New(2, false)

	d.RecordMatch("example.com", "tmpl-1")
	d.RecordMatch("example.com", "tmpl-2")

	// After flagging, the internal hostMatches entry should be cleaned up
	d.mu.Lock()
	_, hasEntry := d.hostMatches["example.com"]
	d.mu.Unlock()
	assert.False(t, hasEntry, "hostMatches should be cleaned up after flagging")
}

func TestDetectorEmptyHost(t *testing.T) {
	d := New(2, false)
	assert.False(t, d.RecordMatch("", "tmpl-1"))
	assert.False(t, d.IsFlagged(""))
}

func TestDetectorMatchCountFlagged(t *testing.T) {
	d := New(3, false)
	d.RecordMatch("example.com", "a")
	d.RecordMatch("example.com", "b")
	d.RecordMatch("example.com", "c")

	// Once flagged, MatchCount returns the threshold
	assert.Equal(t, 3, d.MatchCount("example.com"))
}
