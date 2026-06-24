package httpclientpool

import (
	"fmt"
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
