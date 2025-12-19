package httpclientpool

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/ratelimit"
	urlutil "github.com/projectdiscovery/utils/url"
)

type PerHostRateLimitPool struct {
	cache       *expirable.LRU[string, *rateLimitEntry]
	capacity    int
	mu          sync.Mutex
	options     *types.Options
	maxLifetime time.Duration // Maximum lifetime for entries regardless of access

	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
}

type rateLimitEntry struct {
	limiter           *ratelimit.Limiter
	createdAt         time.Time
	accessCount       atomic.Uint64
	requestCount      atomic.Uint64
	firstRequestAt    atomic.Int64 // UnixNano timestamp
	lastRequestAt     atomic.Int64 // UnixNano timestamp
	requestTimestamps []int64      // Ring buffer of recent request timestamps for pps calculation
	requestMu         sync.Mutex
}

func NewPerHostRateLimitPool(size int, maxIdleTime, maxLifetime time.Duration, options *types.Options) *PerHostRateLimitPool {
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

	pool := &PerHostRateLimitPool{
		cache: expirable.NewLRU[string, *rateLimitEntry](
			size,
			func(key string, value *rateLimitEntry) {
				if value.limiter != nil {
					value.limiter.Stop()
				}
				gologger.Debug().Msgf("[perhost-ratelimit-pool] Evicted rate limiter for %s (age: %v, accesses: %d)",
					key, time.Since(value.createdAt), value.accessCount.Load())
			},
			ttl,
		),
		capacity:    size,
		options:     options,
		maxLifetime: maxLifetime,
	}

	return pool
}

func (p *PerHostRateLimitPool) GetOrCreate(
	host string,
) (*ratelimit.Limiter, error) {
	normalizedHost := normalizeHostForRateLimit(host)

	// Try to get entry (this refreshes TTL in expirable LRU)
	if entry, ok := p.cache.Get(normalizedHost); ok {
		// Check if entry has exceeded maxLifetime
		if p.maxLifetime > 0 && time.Since(entry.createdAt) > p.maxLifetime {
			// Entry is too old, need to evict and recreate
			// Acquire lock to safely evict
			p.mu.Lock()
			// Double-check after acquiring lock (another goroutine might have evicted it)
			if entry, ok := p.cache.Peek(normalizedHost); ok {
				// Check maxLifetime again (entry might have been replaced)
				if time.Since(entry.createdAt) > p.maxLifetime {
					if entry.limiter != nil {
						entry.limiter.Stop()
					}
					p.cache.Remove(normalizedHost)
					p.evictions.Add(1)
					// Fall through to create new entry
				} else {
					// Entry was replaced or is now valid
					entry.accessCount.Add(1)
					p.hits.Add(1)
					p.mu.Unlock()
					return entry.limiter, nil
				}
			}
			// Entry was evicted or doesn't exist, continue to create new one
		} else {
			// Entry is valid (not expired by maxLifetime)
			entry.accessCount.Add(1)
			p.hits.Add(1)
			return entry.limiter, nil
		}
	} else {
		// Entry doesn't exist, acquire lock to create
		p.mu.Lock()
	}

	// At this point we have the lock and need to create a new entry
	defer p.mu.Unlock()

	// Double-check after acquiring lock (another goroutine might have created it)
	if entry, ok := p.cache.Peek(normalizedHost); ok {
		// Check maxLifetime
		if p.maxLifetime > 0 && time.Since(entry.createdAt) > p.maxLifetime {
			// Entry is too old, evict it
			if entry.limiter != nil {
				entry.limiter.Stop()
			}
			p.cache.Remove(normalizedHost)
			p.evictions.Add(1)
		} else {
			// Entry exists and is valid
			entry.accessCount.Add(1)
			p.hits.Add(1)
			return entry.limiter, nil
		}
	}

	p.misses.Add(1)

	// Create new rate limiter for this host
	limiter := utils.GetRateLimiter(context.Background(), p.options.RateLimit, p.options.RateLimitDuration)

	entry := &rateLimitEntry{
		limiter:           limiter,
		createdAt:         time.Now(),
		requestTimestamps: make([]int64, 0, 100), // Track last 100 requests for pps calculation
	}
	entry.accessCount.Store(1)

	evicted := p.cache.Add(normalizedHost, entry)
	if evicted {
		p.evictions.Add(1)
	}

	return limiter, nil
}

func (p *PerHostRateLimitPool) EvictHost(host string) bool {
	normalizedHost := normalizeHostForRateLimit(host)

	// Get entry before removing to stop limiter
	entry, ok := p.cache.Peek(normalizedHost)
	if ok && entry != nil && entry.limiter != nil {
		entry.limiter.Stop()
	}

	existed := p.cache.Remove(normalizedHost)
	if existed {
		p.evictions.Add(1)
	}
	return existed
}

func (p *PerHostRateLimitPool) EvictAll() {
	keys := p.cache.Keys()
	for _, key := range keys {
		if entry, ok := p.cache.Peek(key); ok && entry != nil && entry.limiter != nil {
			entry.limiter.Stop()
		}
	}
	count := p.cache.Len()
	p.cache.Purge()
	p.evictions.Add(uint64(count))
}

func (p *PerHostRateLimitPool) Size() int {
	return p.cache.Len()
}

func (p *PerHostRateLimitPool) Stats() RateLimitPoolStats {
	return RateLimitPoolStats{
		Hits:      p.hits.Load(),
		Misses:    p.misses.Load(),
		Evictions: p.evictions.Load(),
		Size:      p.Size(),
	}
}

func (p *PerHostRateLimitPool) Close() {
	p.EvictAll()
}

// normalizeHostForRateLimit extracts and normalizes host:port from URL for rate limit pool
// This ensures all requests to the same host:port use the same rate limiter, regardless of path
func normalizeHostForRateLimit(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		// If parsing fails, try to extract host:port manually
		// This handles cases where the URL might be malformed
		return extractHostPortFromString(rawURL)
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
		return extractHostPortFromString(rawURL)
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

// extractHostPortFromString attempts to extract host:port from a string when URL parsing fails
func extractHostPortFromString(s string) string {
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

type RateLimitPoolStats struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Size      int
}

func (p *PerHostRateLimitPool) GetLimiterForHost(host string) (*ratelimit.Limiter, bool) {
	normalizedHost := normalizeHostForRateLimit(host)

	if entry, ok := p.cache.Peek(normalizedHost); ok {
		return entry.limiter, true
	}
	return nil, false
}

func (p *PerHostRateLimitPool) ListAllLimiters() []string {
	return p.cache.Keys()
}

type RateLimitInfo struct {
	Host        string
	CreatedAt   time.Time
	AccessCount uint64
	Age         time.Duration
}

func (p *PerHostRateLimitPool) GetRateLimitInfo(host string) *RateLimitInfo {
	normalizedHost := normalizeHostForRateLimit(host)

	entry, ok := p.cache.Peek(normalizedHost)
	if !ok {
		return nil
	}

	now := time.Now()

	return &RateLimitInfo{
		Host:        normalizedHost,
		CreatedAt:   entry.createdAt,
		AccessCount: entry.accessCount.Load(),
		Age:         now.Sub(entry.createdAt),
	}
}

func (p *PerHostRateLimitPool) GetAllRateLimitInfo() []*RateLimitInfo {
	infos := []*RateLimitInfo{}
	for _, key := range p.cache.Keys() {
		if info := p.GetRateLimitInfo(key); info != nil {
			infos = append(infos, info)
		}
	}
	return infos
}

func (p *PerHostRateLimitPool) Resize(size int) int {
	evicted := p.cache.Resize(size)
	p.capacity = size
	return evicted
}

func (p *PerHostRateLimitPool) Cap() int {
	return p.capacity
}

// RecordRequest records a request timestamp for a host to calculate pps
func (p *PerHostRateLimitPool) RecordRequest(host string) {
	normalizedHost := normalizeHostForRateLimit(host)
	entry, ok := p.cache.Peek(normalizedHost)
	if !ok || entry == nil {
		return
	}

	now := time.Now().UnixNano()
	entry.requestCount.Add(1)

	// Set first request time if not set
	if entry.firstRequestAt.Load() == 0 {
		entry.firstRequestAt.Store(now)
	}
	entry.lastRequestAt.Store(now)

	// Track recent timestamps for pps calculation (keep last 100)
	entry.requestMu.Lock()
	entry.requestTimestamps = append(entry.requestTimestamps, now)
	if len(entry.requestTimestamps) > 100 {
		// Keep only last 100 timestamps
		entry.requestTimestamps = entry.requestTimestamps[len(entry.requestTimestamps)-100:]
	}
	entry.requestMu.Unlock()
}

// calculatePPS calculates requests per second for a host based on recent requests
func (p *PerHostRateLimitPool) calculatePPS(entry *rateLimitEntry) float64 {
	if entry == nil {
		return 0
	}

	entry.requestMu.Lock()
	defer entry.requestMu.Unlock()

	if len(entry.requestTimestamps) < 2 {
		// Need at least 2 requests to calculate pps
		return 0
	}

	now := time.Now().UnixNano()
	// Calculate pps based on requests in the last second
	oneSecondAgo := now - int64(time.Second)
	recentRequests := 0
	for i := len(entry.requestTimestamps) - 1; i >= 0; i-- {
		if entry.requestTimestamps[i] >= oneSecondAgo {
			recentRequests++
		} else {
			break
		}
	}

	// If we have recent requests, use them; otherwise calculate from total time span
	if recentRequests > 0 {
		return float64(recentRequests)
	}

	// Fallback: calculate average pps from first to last request
	first := entry.firstRequestAt.Load()
	last := entry.lastRequestAt.Load()
	if first == 0 || last == 0 || last <= first {
		return 0
	}

	duration := time.Duration(last - first)
	if duration <= 0 {
		return 0
	}

	totalRequests := entry.requestCount.Load()
	if totalRequests < 2 {
		return 0
	}

	return float64(totalRequests) / duration.Seconds()
}

func (p *PerHostRateLimitPool) PrintStats() {
	stats := p.Stats()
	if stats.Size == 0 {
		return
	}
	gologger.Info().Msgf("[perhost-ratelimit-pool] Rate limit stats: Hits=%d Misses=%d HitRate=%.1f%% Hosts=%d",
		stats.Hits, stats.Misses,
		float64(stats.Hits)*100/float64(stats.Hits+stats.Misses+1),
		stats.Size)
}

// PrintPerHostPPSStats prints requests per second for each host
func (p *PerHostRateLimitPool) PrintPerHostPPSStats() {
	if p.Size() == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hostStats := []struct {
		host     string
		pps      float64
		requests uint64
		age      time.Duration
	}{}

	for _, key := range p.cache.Keys() {
		entry, ok := p.cache.Peek(key)
		if !ok || entry == nil {
			continue
		}

		pps := p.calculatePPS(entry)
		requests := entry.requestCount.Load()
		age := time.Since(entry.createdAt)

		hostStats = append(hostStats, struct {
			host     string
			pps      float64
			requests uint64
			age      time.Duration
		}{
			host:     key,
			pps:      pps,
			requests: requests,
			age:      age,
		})
	}

	if len(hostStats) == 0 {
		return
	}

	gologger.Info().Msgf("[perhost-ratelimit-pool] Per-host requests per second (pps):")
	for _, stat := range hostStats {
		gologger.Info().Msgf("  %s: %.2f pps (total: %d requests, age: %v)",
			stat.host, stat.pps, stat.requests, stat.age.Round(time.Second))
	}
}
