package httpclientpool

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
)

// HTTPToHTTPSPortTracker tracks host:port combinations that require HTTPS
// This is used to automatically detect and correct cases where HTTP requests
// are sent to HTTPS ports (detected via 400 error with specific message)
type HTTPToHTTPSPortTracker struct {
	ports *mapsutil.SyncLockMap[string, bool]

	// Statistics
	totalDetections atomic.Uint64
	totalCorrections atomic.Uint64
}

// NewHTTPToHTTPSPortTracker creates a new HTTP-to-HTTPS port tracker
func NewHTTPToHTTPSPortTracker() *HTTPToHTTPSPortTracker {
	return &HTTPToHTTPSPortTracker{
		ports: mapsutil.NewSyncLockMap[string, bool](),
	}
}

// RecordHTTPToHTTPSPort records that a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RecordHTTPToHTTPSPort(hostPort string) {
	if hostPort == "" {
		return
	}

	normalizedHostPort := normalizeHostPortForTracker(hostPort)
	if normalizedHostPort == "" {
		return
	}

	// Check if already recorded
	if _, exists := t.ports.Get(normalizedHostPort); exists {
		return // Already recorded, no need to log again
	}

	// Record the host:port as requiring HTTPS
	_ = t.ports.Set(normalizedHostPort, true)
	t.totalDetections.Add(1)

	gologger.Debug().Msgf("[http-to-https-tracker] Detected HTTP-to-HTTPS port mismatch for %s", normalizedHostPort)
}

// RequiresHTTPS checks if a host:port requires HTTPS
func (t *HTTPToHTTPSPortTracker) RequiresHTTPS(hostPort string) bool {
	if hostPort == "" {
		return false
	}

	normalizedHostPort := normalizeHostPortForTracker(hostPort)
	if normalizedHostPort == "" {
		return false
	}

	requiresHTTPS, ok := t.ports.Get(normalizedHostPort)
	if !ok {
		return false
	}

	if requiresHTTPS {
		t.totalCorrections.Add(1)
	}

	return requiresHTTPS
}

// Stats returns statistics about the tracker
func (t *HTTPToHTTPSPortTracker) Stats() HTTPToHTTPSPortStats {
	// Note: SyncLockMap doesn't have a direct Len() method
	// We track detections instead, which gives us the number of unique host:port combinations
	// For exact count, we'd need to maintain a separate counter
	return HTTPToHTTPSPortStats{
		TotalDetections:  t.totalDetections.Load(),
		TotalCorrections: t.totalCorrections.Load(),
		TrackedPorts:     int(t.totalDetections.Load()), // Approximate: each detection is a unique host:port
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

// normalizeHostPortForTracker extracts and normalizes host:port from URL
// Returns format: "hostname:port" (e.g., "example.com:443", "example.com:2087")
func normalizeHostPortForTracker(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		// If parsing fails, try to extract host:port manually
		return extractHostPortFromStringForHTTPS(rawURL)
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Extract hostname
	hostname := parsed.Hostname()
	if hostname == "" {
		// Fallback: try to extract from Host field
		host := parsed.Host
		if host != "" {
			// Split host:port if port is present
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostname = h
			} else {
				hostname = host
			}
		}
	}

	if hostname == "" {
		return extractHostPortFromStringForHTTPS(rawURL)
	}

	port := parsed.Port()
	if port == "" {
		// Use default ports based on scheme
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Return just hostname:port (no scheme prefix)
	return fmt.Sprintf("%s:%s", hostname, port)
}

// extractHostPortFromStringForHTTPS attempts to extract host:port from a string when URL parsing fails
func extractHostPortFromStringForHTTPS(s string) string {
	original := s
	scheme := "http"

	// Remove scheme prefix if present
	if strings.HasPrefix(s, "http://") {
		s = strings.TrimPrefix(s, "http://")
		scheme = "http"
	} else if strings.HasPrefix(s, "https://") {
		s = strings.TrimPrefix(s, "https://")
		scheme = "https"
	}

	// Extract up to first /, ?, #, space, or newline (path/query/fragment separator)
	if idx := strings.IndexAny(s, "/?# \n\r\t"); idx != -1 {
		s = s[:idx]
	}

	if s == "" {
		return original // Return original if we can't extract anything
	}

	// Validate and split host:port
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		// Valid host:port format
		if port == "" {
			// Port is empty, use default
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		// Return just host:port (no scheme prefix)
		return fmt.Sprintf("%s:%s", host, port)
	}

	// No port in string, add default port
	if scheme == "https" {
		return fmt.Sprintf("%s:443", s)
	}
	return fmt.Sprintf("%s:80", s)
}

