package honeypotdetector

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestThresholdBoundary(t *testing.T) {
	t.Parallel()

	d := New(2)
	host := "example.com"

	require.False(t, d.RecordMatch(host, "t1"), "flagging should not happen at N-1 matches")
	require.True(t, d.RecordMatch(host, "t2"), "flagging should happen at exactly N distinct template IDs")
	require.True(t, d.IsFlagged(host))

	// Once flagged, additional distinct matches should not re-trigger the boundary condition.
	require.False(t, d.RecordMatch(host, "t3"))
}

func TestDeduplication(t *testing.T) {
	t.Parallel()

	d := New(2)
	host := "example.com"

	require.False(t, d.RecordMatch(host, "t1"))
	require.False(t, d.RecordMatch(host, "t1"), "same templateID on same host must count once")
	require.True(t, d.RecordMatch(host, "t2"))
	require.True(t, d.IsFlagged(host))
}

func TestHostIsolation(t *testing.T) {
	t.Parallel()

	d := New(2)

	require.False(t, d.RecordMatch("example-a.com", "t1"))
	require.False(t, d.RecordMatch("example-b.com", "t1"))
	require.True(t, d.RecordMatch("example-a.com", "t2"), "host A should be flagged independently")

	require.True(t, d.IsFlagged("example-a.com"))
	require.False(t, d.IsFlagged("example-b.com"))
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	const (
		threshold  = 10
		goroutines = 100
	)

	d := New(threshold)
	host := "example.com"

	var justFlaggedCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if d.RecordMatch(host, fmt.Sprintf("t-%d", i)) {
				justFlaggedCount.Add(1)
			}
		}()
	}

	wg.Wait()

	require.True(t, d.IsFlagged(host))
	require.Equal(t, int32(1), justFlaggedCount.Load(), "exactly one goroutine should trigger the boundary")
}

func TestHostNormalization(t *testing.T) {
	t.Parallel()

	d := New(2)

	// Scheme + trailing slash must be stripped so these map to the same normalized host.
	require.False(t, d.RecordMatch("https://example.com/", "t1"))
	require.True(t, d.RecordMatch("http://example.com", "t2"))
	require.True(t, d.IsFlagged("example.com"))

	// Explicit port should keep it distinct (example.com and example.com:443 are different keys).
	d2 := New(1)
	require.True(t, d2.RecordMatch("example.com:443", "t1"))
	require.True(t, d2.IsFlagged("example.com:443"))
	require.False(t, d2.IsFlagged("example.com"), "host without explicit port must not share the same key")

	// IPv6 should be canonicalized, and bracketed host:port should keep bracketed form when port is present.
	d3 := New(1)
	require.True(t, d3.RecordMatch("http://[2001:db8::1]/", "t1"))
	require.True(t, d3.IsFlagged("2001:db8::1"))
	require.True(t, d3.IsFlagged("[2001:db8::1]"))

	d4 := New(1)
	require.True(t, d4.RecordMatch("[2001:db8::1]:443", "t1"))
	require.True(t, d4.IsFlagged("[2001:db8::1]:443"))
	require.False(t, d4.IsFlagged("2001:db8::1"), "IPv6 with explicit port must not share the same key as IPv6 without port")
}
