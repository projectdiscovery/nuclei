package httpclientpool

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/projectdiscovery/gologger"
	urlutil "github.com/projectdiscovery/utils/url"
)

type ConnectionReuseTracker struct {
	cache    *expirable.LRU[string, *connectionReuseEntry]
	capacity int
	mu       sync.Mutex

	totalConnections    atomic.Uint64
	totalReused         atomic.Uint64
	totalNewConnections atomic.Uint64

	// Protocol-specific counters
	totalHTTPConnections     atomic.Uint64
	totalHTTPSConnections    atomic.Uint64
	totalHTTPReused          atomic.Uint64
	totalHTTPSReused         atomic.Uint64
	totalHTTPNewConnections  atomic.Uint64
	totalHTTPSNewConnections atomic.Uint64
}

type connectionReuseEntry struct {
	host                string
	createdAt           time.Time
	totalConnections    atomic.Uint64
	totalReused         atomic.Uint64
	totalNewConnections atomic.Uint64
	accessCount         atomic.Uint64

	// Protocol-specific counters per host
	totalHTTPConnections     atomic.Uint64
	totalHTTPSConnections    atomic.Uint64
	totalHTTPReused          atomic.Uint64
	totalHTTPSReused         atomic.Uint64
	totalHTTPNewConnections  atomic.Uint64
	totalHTTPSNewConnections atomic.Uint64
}

func NewConnectionReuseTracker(size int, maxIdleTime, maxLifetime time.Duration) *ConnectionReuseTracker {
	if size <= 0 {
		size = 1024
	}
	// For global scan tracking, use very long TTL to keep entries for entire scan duration
	// Default to 24 hours if not specified, which should cover even very long scans
	if maxIdleTime == 0 {
		maxIdleTime = 24 * time.Hour
	}
	if maxLifetime == 0 {
		maxLifetime = 24 * time.Hour
	}

	ttl := maxIdleTime
	if maxLifetime < maxIdleTime {
		ttl = maxLifetime
	}

	tracker := &ConnectionReuseTracker{
		cache: expirable.NewLRU[string, *connectionReuseEntry](
			size,
			func(key string, value *connectionReuseEntry) {
				gologger.Debug().Msgf("[connection-reuse-tracker] Evicted entry for %s (age: %v, connections: %d, reused: %d)",
					key, time.Since(value.createdAt), value.totalConnections.Load(), value.totalReused.Load())
			},
			ttl,
		),
		capacity: size,
	}

	return tracker
}

// RecordConnection records a connection event (new or reused) for a host
func (t *ConnectionReuseTracker) RecordConnection(hostname string, reused bool) {
	if hostname == "" {
		return
	}

	normalizedHost := normalizeHostForConnectionReuse(hostname)
	if normalizedHost == "" {
		return
	}

	// Detect protocol (HTTP vs HTTPS) from the original hostname/URL
	isHTTPS := isHTTPSConnection(hostname)

	t.totalConnections.Add(1)
	if reused {
		t.totalReused.Add(1)
	} else {
		t.totalNewConnections.Add(1)
	}

	// Update protocol-specific global counters
	if isHTTPS {
		t.totalHTTPSConnections.Add(1)
		if reused {
			t.totalHTTPSReused.Add(1)
		} else {
			t.totalHTTPSNewConnections.Add(1)
		}
	} else {
		t.totalHTTPConnections.Add(1)
		if reused {
			t.totalHTTPReused.Add(1)
		} else {
			t.totalHTTPNewConnections.Add(1)
		}
	}

	entry := t.getOrCreateEntry(normalizedHost)
	if entry == nil {
		return
	}

	entry.totalConnections.Add(1)
	entry.accessCount.Add(1)
	if reused {
		entry.totalReused.Add(1)
	} else {
		entry.totalNewConnections.Add(1)
	}

	// Update protocol-specific per-host counters
	if isHTTPS {
		entry.totalHTTPSConnections.Add(1)
		if reused {
			entry.totalHTTPSReused.Add(1)
		} else {
			entry.totalHTTPSNewConnections.Add(1)
		}
	} else {
		entry.totalHTTPConnections.Add(1)
		if reused {
			entry.totalHTTPReused.Add(1)
		} else {
			entry.totalHTTPNewConnections.Add(1)
		}
	}
}

// isHTTPSConnection detects if a connection is HTTPS based on the URL/hostname
func isHTTPSConnection(hostname string) bool {
	if hostname == "" {
		return false
	}

	// Check for https:// scheme prefix
	if strings.HasPrefix(strings.ToLower(hostname), "https://") {
		return true
	}

	// Check if port is 443 (HTTPS default port)
	if strings.HasSuffix(hostname, ":443") {
		return true
	}

	// Try to parse as URL to get scheme
	parsed, err := urlutil.Parse(hostname)
	if err == nil && parsed.Scheme == "https" {
		return true
	}

	// Default to HTTP if we can't determine
	return false
}

func (t *ConnectionReuseTracker) getOrCreateEntry(normalizedHost string) *connectionReuseEntry {
	if entry, ok := t.cache.Get(normalizedHost); ok {
		return entry
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check after acquiring lock
	if entry, ok := t.cache.Peek(normalizedHost); ok {
		return entry
	}

	entry := &connectionReuseEntry{
		host:      normalizedHost,
		createdAt: time.Now(),
	}
	entry.totalConnections.Store(0)
	entry.totalReused.Store(0)
	entry.totalNewConnections.Store(0)
	entry.accessCount.Store(0)
	entry.totalHTTPConnections.Store(0)
	entry.totalHTTPSConnections.Store(0)
	entry.totalHTTPReused.Store(0)
	entry.totalHTTPSReused.Store(0)
	entry.totalHTTPNewConnections.Store(0)
	entry.totalHTTPSNewConnections.Store(0)

	evicted := t.cache.Add(normalizedHost, entry)
	if evicted {
		_ = evicted
		// Entry was evicted, but we still return the new entry
	}

	return entry
}

func (t *ConnectionReuseTracker) Size() int {
	return t.cache.Len()
}

func (t *ConnectionReuseTracker) Stats() ConnectionReuseStats {
	return ConnectionReuseStats{
		TotalConnections:         t.totalConnections.Load(),
		TotalReused:              t.totalReused.Load(),
		TotalNewConnections:      t.totalNewConnections.Load(),
		Hosts:                    t.Size(),
		TotalHTTPConnections:     t.totalHTTPConnections.Load(),
		TotalHTTPSConnections:    t.totalHTTPSConnections.Load(),
		TotalHTTPReused:          t.totalHTTPReused.Load(),
		TotalHTTPSReused:         t.totalHTTPSReused.Load(),
		TotalHTTPNewConnections:  t.totalHTTPNewConnections.Load(),
		TotalHTTPSNewConnections: t.totalHTTPSNewConnections.Load(),
	}
}

type ConnectionReuseStats struct {
	TotalConnections         uint64
	TotalReused              uint64
	TotalNewConnections      uint64
	Hosts                    int
	TotalHTTPConnections     uint64
	TotalHTTPSConnections    uint64
	TotalHTTPReused          uint64
	TotalHTTPSReused         uint64
	TotalHTTPNewConnections  uint64
	TotalHTTPSNewConnections uint64
}

func (t *ConnectionReuseTracker) PrintStats() {
	stats := t.Stats()
	reuseRate := float64(0)
	if stats.TotalConnections > 0 {
		reuseRate = float64(stats.TotalReused) * 100 / float64(stats.TotalConnections)
	}

	httpReuseRate := float64(0)
	if stats.TotalHTTPConnections > 0 {
		httpReuseRate = float64(stats.TotalHTTPReused) * 100 / float64(stats.TotalHTTPConnections)
	}

	httpsReuseRate := float64(0)
	if stats.TotalHTTPSConnections > 0 {
		httpsReuseRate = float64(stats.TotalHTTPSReused) * 100 / float64(stats.TotalHTTPSConnections)
	}

	gologger.Info().Msgf("[connection-reuse-tracker] Connection reuse stats: Total=%d Reused=%d New=%d ReuseRate=%.1f%% Hosts=%d",
		stats.TotalConnections, stats.TotalReused, stats.TotalNewConnections, reuseRate, stats.Hosts)
	gologger.Info().Msgf("[connection-reuse-tracker] Protocol breakdown: HTTP=%d (Reused=%d, ReuseRate=%.1f%%) HTTPS=%d (Reused=%d, ReuseRate=%.1f%%)",
		stats.TotalHTTPConnections, stats.TotalHTTPReused, httpReuseRate,
		stats.TotalHTTPSConnections, stats.TotalHTTPSReused, httpsReuseRate)
}

func (t *ConnectionReuseTracker) PrintPerHostStats() {
	if t.Size() == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostStats := []struct {
		host                  string
		totalConnections      uint64
		totalReused           uint64
		totalNewConnections   uint64
		reuseRate             float64
		age                   time.Duration
		totalHTTPConnections  uint64
		totalHTTPSConnections uint64
		totalHTTPReused       uint64
		totalHTTPSReused      uint64
		httpReuseRate         float64
		httpsReuseRate        float64
	}{}

	for _, key := range t.cache.Keys() {
		entry, ok := t.cache.Peek(key)
		if !ok || entry == nil {
			continue
		}

		totalConn := entry.totalConnections.Load()
		totalReused := entry.totalReused.Load()
		totalNew := entry.totalNewConnections.Load()
		reuseRate := float64(0)
		if totalConn > 0 {
			reuseRate = float64(totalReused) * 100 / float64(totalConn)
		}
		age := time.Since(entry.createdAt)

		httpConn := entry.totalHTTPConnections.Load()
		httpsConn := entry.totalHTTPSConnections.Load()
		httpReused := entry.totalHTTPReused.Load()
		httpsReused := entry.totalHTTPSReused.Load()

		httpReuseRate := float64(0)
		if httpConn > 0 {
			httpReuseRate = float64(httpReused) * 100 / float64(httpConn)
		}

		httpsReuseRate := float64(0)
		if httpsConn > 0 {
			httpsReuseRate = float64(httpsReused) * 100 / float64(httpsConn)
		}

		hostStats = append(hostStats, struct {
			host                  string
			totalConnections      uint64
			totalReused           uint64
			totalNewConnections   uint64
			reuseRate             float64
			age                   time.Duration
			totalHTTPConnections  uint64
			totalHTTPSConnections uint64
			totalHTTPReused       uint64
			totalHTTPSReused      uint64
			httpReuseRate         float64
			httpsReuseRate        float64
		}{
			host:                  key,
			totalConnections:      totalConn,
			totalReused:           totalReused,
			totalNewConnections:   totalNew,
			reuseRate:             reuseRate,
			age:                   age,
			totalHTTPConnections:  httpConn,
			totalHTTPSConnections: httpsConn,
			totalHTTPReused:       httpReused,
			totalHTTPSReused:      httpsReused,
			httpReuseRate:         httpReuseRate,
			httpsReuseRate:        httpsReuseRate,
		})
	}

	if len(hostStats) == 0 {
		return
	}

	gologger.Info().Msgf("[connection-reuse-tracker] Per-host connection reuse:")
	for _, stat := range hostStats {
		gologger.Info().Msgf("  %s: %d reused / %d total (%.1f%% reuse rate, age: %v)",
			stat.host, stat.totalReused, stat.totalConnections, stat.reuseRate, stat.age.Round(time.Second))
		if stat.totalHTTPConnections > 0 || stat.totalHTTPSConnections > 0 {
			protocolDetails := []string{}
			if stat.totalHTTPConnections > 0 {
				protocolDetails = append(protocolDetails, fmt.Sprintf("HTTP: %d reused / %d total (%.1f%%)",
					stat.totalHTTPReused, stat.totalHTTPConnections, stat.httpReuseRate))
			}
			if stat.totalHTTPSConnections > 0 {
				protocolDetails = append(protocolDetails, fmt.Sprintf("HTTPS: %d reused / %d total (%.1f%%)",
					stat.totalHTTPSReused, stat.totalHTTPSConnections, stat.httpsReuseRate))
			}
			if len(protocolDetails) > 0 {
				gologger.Info().Msgf("    Protocol breakdown: %s", strings.Join(protocolDetails, ", "))
			}
		}
	}
}

func (t *ConnectionReuseTracker) Close() {
	t.cache.Purge()
}

// normalizeHostForConnectionReuse extracts and normalizes host:port from URL (same as rate limit)
func normalizeHostForConnectionReuse(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		// If parsing fails, try to extract host:port manually
		return extractHostPortFromStringForReuse(rawURL)
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Extract just the hostname (without port) and port separately
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
		return extractHostPortFromStringForReuse(rawURL)
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

// extractHostPortFromStringForReuse attempts to extract host:port from a string when URL parsing fails
func extractHostPortFromStringForReuse(s string) string {
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
