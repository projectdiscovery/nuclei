package httpclientpool

import (
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/projectdiscovery/gologger"
)

// defaultHTTPToHTTPSTrackerSize bounds how many host:port entries the tracker
// keeps in memory. It is an LRU rather than a grow-only map so a long-running
// embedder (e.g. a scan service running for days) does not accumulate one entry
// per unique host:port forever. Evicting the least-recently-used entry only
// costs a single re-detection (one extra 400) if that host:port is scanned
// again later, and the result is re-learned immediately.
const defaultHTTPToHTTPSTrackerSize = 50000

// HTTPToHTTPSPortTracker tracks host:port combinations that require HTTPS
// This is used to automatically detect and correct cases where HTTP requests
// are sent to HTTPS ports (detected via 400 error with specific message).
//
// NOTE: detection and correction apply to the standard net/http (retryablehttp)
// request path only. Unsafe/raw (rawhttp) requests bypass this scheme rewrite.
type HTTPToHTTPSPortTracker struct {
	// ports is a bounded LRU of host:port that require HTTPS
	ports *lru.Cache[string, struct{}]

	// Statistics
	totalDetections  atomic.Uint64
	totalCorrections atomic.Uint64
}

// NewHTTPToHTTPSPortTracker creates a new HTTP-to-HTTPS port tracker
func NewHTTPToHTTPSPortTracker() *HTTPToHTTPSPortTracker {
	return newHTTPToHTTPSPortTrackerWithSize(defaultHTTPToHTTPSTrackerSize)
}

func newHTTPToHTTPSPortTrackerWithSize(size int) *HTTPToHTTPSPortTracker {
	if size <= 0 {
		size = defaultHTTPToHTTPSTrackerSize
	}
	// lru.New only errors on a non-positive size, which is guarded above
	cache, _ := lru.New[string, struct{}](size)
	return &HTTPToHTTPSPortTracker{ports: cache}
}

// RecordHTTPToHTTPSPort records that a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RecordHTTPToHTTPSPort(hostPort string) {
	if hostPort == "" {
		return
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return
	}

	if existed, _ := t.ports.ContainsOrAdd(normalizedHostPort, struct{}{}); existed {
		return // Already recorded, no need to log again
	}
	t.totalDetections.Add(1)

	gologger.Debug().Msgf("[http-to-https-tracker] Detected HTTP-to-HTTPS port mismatch for %s", normalizedHostPort)
}

// RequiresHTTPS checks if a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RequiresHTTPS(hostPort string) bool {
	if hostPort == "" {
		return false
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return false
	}

	// Get (rather than Contains) so active host:ports refresh their LRU
	// recency and are not evicted while still in use.
	_, ok := t.ports.Get(normalizedHostPort)
	return ok
}

// RecordCorrection records that an HTTP->HTTPS correction was actually applied
func (t *HTTPToHTTPSPortTracker) RecordCorrection() {
	t.totalCorrections.Add(1)
}

// Evict removes a host:port from the tracker. It is used to self-heal a false
// positive: when an http->https correction is applied but the https request
// then fails, the original http scheme is retried and, if the entry was wrong,
// evicted so subsequent requests (including those from unrelated templates)
// against the same host:port are not silently broken.
func (t *HTTPToHTTPSPortTracker) Evict(hostPort string) {
	if hostPort == "" {
		return
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return
	}

	if present := t.ports.Remove(normalizedHostPort); present {
		gologger.Debug().Msgf("[http-to-https-tracker] Reverted HTTP-to-HTTPS for %s (https attempt failed, falling back to http)", normalizedHostPort)
	}
}

// Stats returns statistics about the tracker
func (t *HTTPToHTTPSPortTracker) Stats() HTTPToHTTPSPortStats {
	return HTTPToHTTPSPortStats{
		TotalDetections:  t.totalDetections.Load(),
		TotalCorrections: t.totalCorrections.Load(),
		// TrackedPorts is the number of entries currently held in the bounded
		// LRU (may be lower than TotalDetections once eviction kicks in).
		TrackedPorts: t.ports.Len(),
	}
}

// HTTPToHTTPSPortStats contains statistics about the HTTP-to-HTTPS port tracker
type HTTPToHTTPSPortStats struct {
	TotalDetections  uint64
	TotalCorrections uint64
	TrackedPorts     int
}

// PrintStats prints statistics about the tracker
func (t *HTTPToHTTPSPortTracker) PrintStats() {
	stats := t.Stats()
	if stats.TotalDetections == 0 {
		return
	}

	gologger.Info().Msgf("[http-to-https-tracker] HTTP-to-HTTPS port corrections: Detections=%d Corrections=%d TrackedPorts=%d",
		stats.TotalDetections, stats.TotalCorrections, stats.TrackedPorts)
}
