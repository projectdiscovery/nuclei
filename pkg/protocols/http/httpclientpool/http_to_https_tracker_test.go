package httpclientpool

import (
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
