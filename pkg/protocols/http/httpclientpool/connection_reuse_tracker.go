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
}

type connectionReuseEntry struct {
	host                string
	createdAt           time.Time
	totalConnections    atomic.Uint64
	totalReused         atomic.Uint64
	totalNewConnections atomic.Uint64
	accessCount         atomic.Uint64
}

func NewConnectionReuseTracker(size int, maxIdleTime, maxLifetime time.Duration) *ConnectionReuseTracker {
	if size <= 0 {
		size = 1024
	}
	if maxIdleTime == 0 {
		maxIdleTime = 5 * time.Minute
	}
	if maxLifetime == 0 {
		maxLifetime = 30 * time.Minute
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

	t.totalConnections.Add(1)
	if reused {
		t.totalReused.Add(1)
	} else {
		t.totalNewConnections.Add(1)
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
		TotalConnections:    t.totalConnections.Load(),
		TotalReused:         t.totalReused.Load(),
		TotalNewConnections: t.totalNewConnections.Load(),
		Hosts:               t.Size(),
	}
}

type ConnectionReuseStats struct {
	TotalConnections    uint64
	TotalReused         uint64
	TotalNewConnections uint64
	Hosts               int
}

func (t *ConnectionReuseTracker) PrintStats() {
	stats := t.Stats()
	if stats.Hosts == 0 {
		return
	}
	reuseRate := float64(0)
	if stats.TotalConnections > 0 {
		reuseRate = float64(stats.TotalReused) * 100 / float64(stats.TotalConnections)
	}
	gologger.Info().Msgf("[connection-reuse-tracker] Connection reuse stats: Total=%d Reused=%d New=%d ReuseRate=%.1f%% Hosts=%d",
		stats.TotalConnections, stats.TotalReused, stats.TotalNewConnections, reuseRate, stats.Hosts)
}

func (t *ConnectionReuseTracker) PrintPerHostStats() {
	if t.Size() == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostStats := []struct {
		host                string
		totalConnections    uint64
		totalReused         uint64
		totalNewConnections uint64
		reuseRate           float64
		age                 time.Duration
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

		hostStats = append(hostStats, struct {
			host                string
			totalConnections    uint64
			totalReused         uint64
			totalNewConnections uint64
			reuseRate           float64
			age                 time.Duration
		}{
			host:                key,
			totalConnections:    totalConn,
			totalReused:         totalReused,
			totalNewConnections: totalNew,
			reuseRate:           reuseRate,
			age:                 age,
		})
	}

	if len(hostStats) == 0 {
		return
	}

	gologger.Info().Msgf("[connection-reuse-tracker] Per-host connection reuse:")
	for _, stat := range hostStats {
		gologger.Info().Msgf("  %s: %d reused / %d total (%.1f%% reuse rate, age: %v)",
			stat.host, stat.totalReused, stat.totalConnections, stat.reuseRate, stat.age.Round(time.Second))
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
