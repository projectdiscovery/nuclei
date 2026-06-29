package httpclientpool

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPToHTTPSPortTracker_RecordAndRequire(t *testing.T) {
	tr := NewHTTPToHTTPSPortTracker()

	require.False(t, tr.RequiresHTTPS("http://example.com:8443/path"), "unknown host should not require https")

	tr.RecordHTTPToHTTPSPort("http://example.com:8443/path")
	require.True(t, tr.RequiresHTTPS("http://example.com:8443/other"), "recorded host:port should require https regardless of path")
	require.True(t, tr.RequiresHTTPS("https://example.com:8443/"), "lookup must be scheme-independent (keyed by host:port)")

	require.EqualValues(t, 1, tr.Stats().TotalDetections)
}

// TestHTTPToHTTPSPortTracker_Evict guards the fallback mechanism: a wrongly detected
// host:port must be removable so a failed https correction can revert to http
// and stop breaking subsequent (cross-template) requests to the same target.
func TestHTTPToHTTPSPortTracker_Evict(t *testing.T) {
	tr := NewHTTPToHTTPSPortTracker()

	tr.RecordHTTPToHTTPSPort("http://example.com:8080/")
	require.True(t, tr.RequiresHTTPS("http://example.com:8080/"))

	tr.Evict("http://example.com:8080/")
	require.False(t, tr.RequiresHTTPS("http://example.com:8080/"), "evicted host:port must no longer require https")

	// Evicting unknown / empty values must be safe no-ops.
	tr.Evict("")
	tr.Evict("http://not-recorded.example:1234/")
}

// TestHTTPToHTTPSPortTracker_BoundedLRU guards against unbounded memory growth
// in long-running embedders: the tracker must cap the number of host:port
// entries it retains and evict the least-recently-used ones instead of growing
// forever.
func TestHTTPToHTTPSPortTracker_BoundedLRU(t *testing.T) {
	const size = 100
	tr := newHTTPToHTTPSPortTrackerWithSize(size)

	for i := 0; i < size*3; i++ {
		tr.RecordHTTPToHTTPSPort(fmt.Sprintf("http://host%d.example.com:8443/", i))
	}

	// cumulative detections counts every unique host:port ever recorded
	require.EqualValues(t, size*3, tr.Stats().TotalDetections)
	// but the in-memory set is bounded by the LRU capacity
	require.Equal(t, size, tr.Stats().TrackedPorts, "tracker must not grow beyond its LRU capacity")

	// the oldest entry must have been evicted, the newest must remain
	require.False(t, tr.RequiresHTTPS("http://host0.example.com:8443/"), "oldest entry should be evicted")
	require.True(t, tr.RequiresHTTPS(fmt.Sprintf("http://host%d.example.com:8443/", size*3-1)), "newest entry should be retained")
}

// TestHTTPToHTTPSPortTracker_RequiresHTTPSRefreshesLRU guards the recency-refresh
// contract: a lookup must mark the entry as recently used so that an actively
// queried host:port survives eviction over an untouched one.
func TestHTTPToHTTPSPortTracker_RequiresHTTPSRefreshesLRU(t *testing.T) {
	tr := newHTTPToHTTPSPortTrackerWithSize(2)

	tr.RecordHTTPToHTTPSPort("http://a.example.com:8443/")
	tr.RecordHTTPToHTTPSPort("http://b.example.com:8443/")

	require.True(t, tr.RequiresHTTPS("http://a.example.com:8443/"), "lookup should refresh recency")

	tr.RecordHTTPToHTTPSPort("http://c.example.com:8443/")

	require.True(t, tr.RequiresHTTPS("http://a.example.com:8443/"), "refreshed entry should be retained")
	require.False(t, tr.RequiresHTTPS("http://b.example.com:8443/"), "untouched least-recently-used entry should be evicted")
	require.True(t, tr.RequiresHTTPS("http://c.example.com:8443/"))
}

// TestHTTPToHTTPSPortTracker_RecordRefreshesLRU guards the recency-refresh
// contract on the write path: re-recording an existing host:port must mark it
// recently-used so an actively re-detected entry survives eviction over an
// untouched one (a plain ContainsOrAdd would not refresh recency here).
func TestHTTPToHTTPSPortTracker_RecordRefreshesLRU(t *testing.T) {
	tr := newHTTPToHTTPSPortTrackerWithSize(2)

	tr.RecordHTTPToHTTPSPort("http://a.example.com:8443/")
	tr.RecordHTTPToHTTPSPort("http://b.example.com:8443/")

	// re-recording "a" must refresh its recency, making "b" the LRU victim
	tr.RecordHTTPToHTTPSPort("http://a.example.com:8443/")

	tr.RecordHTTPToHTTPSPort("http://c.example.com:8443/")

	require.True(t, tr.RequiresHTTPS("http://a.example.com:8443/"), "re-recorded entry should be retained")
	require.False(t, tr.RequiresHTTPS("http://b.example.com:8443/"), "untouched least-recently-used entry should be evicted")
	require.True(t, tr.RequiresHTTPS("http://c.example.com:8443/"))

	// re-recording an existing host must not inflate the unique-detection count
	require.EqualValues(t, 3, tr.Stats().TotalDetections, "re-recording an existing host:port must not double-count")
}

// TestHTTPToHTTPSPortTracker_ConcurrentRecordCountsOnce ensures that recording
// the same host:port from many goroutines counts it as a single detection.
// PeekOrAdd makes the insert+count atomic; a check-then-add (Get then Add)
// implementation would over-count under the race detector.
func TestHTTPToHTTPSPortTracker_ConcurrentRecordCountsOnce(t *testing.T) {
	tr := NewHTTPToHTTPSPortTracker()

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			tr.RecordHTTPToHTTPSPort("http://race.example.com:8443/")
		}()
	}
	wg.Wait()

	require.EqualValues(t, 1, tr.Stats().TotalDetections, "a unique host:port must be counted exactly once")
	require.Equal(t, 1, tr.Stats().TrackedPorts, "a unique host:port must occupy a single LRU entry")
}

// TestHTTPToHTTPSPortTracker_ZeroValueSafe ensures a zero-value tracker
// (constructed directly rather than via NewHTTPToHTTPSPortTracker) lazily
// initializes its bounded LRU instead of panicking on a nil cache.
func TestHTTPToHTTPSPortTracker_ZeroValueSafe(t *testing.T) {
	var tr HTTPToHTTPSPortTracker

	require.NotPanics(t, func() {
		require.False(t, tr.RequiresHTTPS("http://example.com:8443/"))
		tr.RecordHTTPToHTTPSPort("http://example.com:8443/")
		require.True(t, tr.RequiresHTTPS("http://example.com:8443/"))
		tr.Evict("http://example.com:8443/")
		_ = tr.Stats()
	})
}
