package httpclientpool

import (
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/projectdiscovery/gologger"
)

// HTTPToHTTPSPortTracker tracks host:port combinations that require HTTPS
// This is used to automatically detect and correct cases where HTTP requests
// are sent to HTTPS ports (detected via 400 error with specific message).
//
// NOTE: detection and correction apply to the standard net/http (retryablehttp)
// request path only. Unsafe/raw (rawhttp) requests bypass this scheme rewrite.
type HTTPToHTTPSPortTracker struct {
	// ports is an LRU discovery cache bounded to prevent memory leaks in long-running engines
	ports *expirable.LRU[string, struct{}]

	// Statistics
	totalDetections  atomic.Uint64
	totalCorrections atomic.Uint64
}

// NewHTTPToHTTPSPortTracker creates a new HTTP-to-HTTPS port tracker
func NewHTTPToHTTPSPortTracker() *HTTPToHTTPSPortTracker {
	return &HTTPToHTTPSPortTracker{
		ports: expirable.NewLRU[string, struct{}](4096, nil, 24*time.Hour),
	}
}

// RecordHTTPToHTTPSPort records that a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RecordHTTPToHTTPSPort(hostPort string) {
	if hostPort == "" || t.ports == nil {
		return
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return
	}

	if t.ports.Contains(normalizedHostPort) {
		return // Already recorded, no need to log again
	}
	t.ports.Add(normalizedHostPort, struct{}{})
	t.totalDetections.Add(1)

	gologger.Debug().Msgf("[http-to-https-tracker] Detected HTTP-to-HTTPS port mismatch for %s", normalizedHostPort)
}

// RequiresHTTPS checks if a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RequiresHTTPS(hostPort string) bool {
	if hostPort == "" || t.ports == nil {
		return false
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return false
	}

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
	if hostPort == "" || t.ports == nil {
		return
	}

	normalizedHostPort := normalizeHostPort(hostPort)
	if normalizedHostPort == "" {
		return
	}

	if t.ports.Remove(normalizedHostPort) {
		gologger.Debug().Msgf("[http-to-https-tracker] Reverted HTTP-to-HTTPS for %s (https attempt failed, falling back to http)", normalizedHostPort)
	}
}

// Purge removes all tracked entries from the tracker
func (t *HTTPToHTTPSPortTracker) Purge() {
	if t.ports != nil {
		t.ports.Purge()
	}
}

// Stats returns statistics about the tracker
func (t *HTTPToHTTPSPortTracker) Stats() HTTPToHTTPSPortStats {
	tracked := 0
	if t.ports != nil {
		tracked = t.ports.Len()
	}
	return HTTPToHTTPSPortStats{
		TotalDetections:  t.totalDetections.Load(),
		TotalCorrections: t.totalCorrections.Load(),
		TrackedPorts:     tracked,
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
