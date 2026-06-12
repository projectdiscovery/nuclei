package httpclientpool

import (
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
)

// HTTPToHTTPSPortTracker tracks host:port combinations that require HTTPS
// This is used to automatically detect and correct cases where HTTP requests
// are sent to HTTPS ports (detected via 400 error with specific message)
type HTTPToHTTPSPortTracker struct {
	// ports is a grow-only discovery cache, sync.Map gives lock-free reads
	ports sync.Map // map[string]struct{}

	// Statistics
	totalDetections  atomic.Uint64
	totalCorrections atomic.Uint64
}

// NewHTTPToHTTPSPortTracker creates a new HTTP-to-HTTPS port tracker
func NewHTTPToHTTPSPortTracker() *HTTPToHTTPSPortTracker {
	return &HTTPToHTTPSPortTracker{}
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

	if _, loaded := t.ports.LoadOrStore(normalizedHostPort, struct{}{}); loaded {
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

	_, ok := t.ports.Load(normalizedHostPort)
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

	if _, loaded := t.ports.LoadAndDelete(normalizedHostPort); loaded {
		gologger.Debug().Msgf("[http-to-https-tracker] Reverted HTTP-to-HTTPS for %s (https attempt failed, falling back to http)", normalizedHostPort)
	}
}

// Stats returns statistics about the tracker
func (t *HTTPToHTTPSPortTracker) Stats() HTTPToHTTPSPortStats {
	return HTTPToHTTPSPortStats{
		TotalDetections:  t.totalDetections.Load(),
		TotalCorrections: t.totalCorrections.Load(),
		// detections are incremented once per unique host:port, so this is exact
		TrackedPorts: int(t.totalDetections.Load()),
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
