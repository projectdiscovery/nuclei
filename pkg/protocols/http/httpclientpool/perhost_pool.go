package httpclientpool

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

type PerHostClientPool struct {
	cache    *expirable.LRU[string, *clientEntry]
	capacity int
	mu       sync.Mutex

	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
}

type clientEntry struct {
	client      *retryablehttp.Client
	createdAt   time.Time
	accessCount atomic.Uint64
}

func NewPerHostClientPool(size int, maxIdleTime, maxLifetime time.Duration) *PerHostClientPool {
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

	pool := &PerHostClientPool{
		cache: expirable.NewLRU[string, *clientEntry](
			size,
			func(key string, value *clientEntry) {
				gologger.Debug().Msgf("[perhost-pool] Evicted client for %s (age: %v, accesses: %d)",
					key, time.Since(value.createdAt), value.accessCount.Load())
			},
			ttl,
		),
		capacity: size,
	}

	return pool
}

func (p *PerHostClientPool) GetOrCreate(
	host string,
	createFunc func() (*retryablehttp.Client, error),
) (*retryablehttp.Client, error) {
	normalizedHost := normalizeHost(host)

	if entry, ok := p.cache.Get(normalizedHost); ok {
		entry.accessCount.Add(1)
		p.hits.Add(1)
		return entry.client, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.cache.Peek(normalizedHost); ok {
		entry.accessCount.Add(1)
		p.hits.Add(1)
		return entry.client, nil
	}

	p.misses.Add(1)

	client, err := createFunc()
	if err != nil {
		return nil, err
	}

	entry := &clientEntry{
		client:    client,
		createdAt: time.Now(),
	}
	entry.accessCount.Store(1)

	evicted := p.cache.Add(normalizedHost, entry)
	if evicted {
		p.evictions.Add(1)
	}

	return client, nil
}

func (p *PerHostClientPool) EvictHost(host string) bool {
	normalizedHost := normalizeHost(host)
	existed := p.cache.Remove(normalizedHost)

	if existed {
		p.evictions.Add(1)
	}
	return existed
}

func (p *PerHostClientPool) EvictAll() {
	count := p.cache.Len()
	p.cache.Purge()
	p.evictions.Add(uint64(count))
}

func (p *PerHostClientPool) Size() int {
	return p.cache.Len()
}

func (p *PerHostClientPool) Stats() PoolStats {
	return PoolStats{
		Hits:      p.hits.Load(),
		Misses:    p.misses.Load(),
		Evictions: p.evictions.Load(),
		Size:      p.Size(),
	}
}

func (p *PerHostClientPool) Close() {
	p.EvictAll()
}

func normalizeHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := parsed.Host
	if host == "" {
		host = parsed.Hostname()
	}

	port := parsed.Port()
	if port != "" {
		return fmt.Sprintf("%s://%s:%s", scheme, parsed.Hostname(), port)
	}

	if scheme == "https" && port == "" {
		return fmt.Sprintf("%s://%s:443", scheme, parsed.Hostname())
	}
	if scheme == "http" && port == "" {
		return fmt.Sprintf("%s://%s:80", scheme, parsed.Hostname())
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

type PoolStats struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Size      int
}

func (p *PerHostClientPool) GetClientForHost(host string) (*retryablehttp.Client, bool) {
	normalizedHost := normalizeHost(host)

	if entry, ok := p.cache.Peek(normalizedHost); ok {
		return entry.client, true
	}
	return nil, false
}

func (p *PerHostClientPool) ListAllClients() []string {
	return p.cache.Keys()
}

type ClientInfo struct {
	Host        string
	CreatedAt   time.Time
	AccessCount uint64
	Age         time.Duration
}

func (p *PerHostClientPool) GetClientInfo(host string) *ClientInfo {
	normalizedHost := normalizeHost(host)

	entry, ok := p.cache.Peek(normalizedHost)
	if !ok {
		return nil
	}

	now := time.Now()

	return &ClientInfo{
		Host:        normalizedHost,
		CreatedAt:   entry.createdAt,
		AccessCount: entry.accessCount.Load(),
		Age:         now.Sub(entry.createdAt),
	}
}

func (p *PerHostClientPool) GetAllClientInfo() []*ClientInfo {
	infos := []*ClientInfo{}
	for _, key := range p.cache.Keys() {
		if info := p.GetClientInfo(key); info != nil {
			infos = append(infos, info)
		}
	}
	return infos
}

func (p *PerHostClientPool) Resize(size int) int {
	evicted := p.cache.Resize(size)
	p.capacity = size
	return evicted
}

func (p *PerHostClientPool) Cap() int {
	return p.capacity
}

func (p *PerHostClientPool) PrintStats() {
	stats := p.Stats()
	if stats.Size == 0 {
		return
	}
	gologger.Verbose().Msgf("[perhost-pool] Connection reuse stats: Hits=%d Misses=%d HitRate=%.1f%% Hosts=%d",
		stats.Hits, stats.Misses,
		float64(stats.Hits)*100/float64(stats.Hits+stats.Misses+1),
		stats.Size)
}

func (p *PerHostClientPool) PrintTransportStats() {
}
