package httpclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	// DefaultShardCount is the default number of shards when auto-calculated
	DefaultShardCount = 16
	// MinShardCount is the minimum number of shards
	MinShardCount = 4
	// MaxShardCount is the maximum number of shards
	MaxShardCount = 256
)

// ShardedClientPool manages HTTP clients distributed across multiple shards
// Each shard handles a subset of hosts, enabling connection reuse while
// preventing overload of a single client
type ShardedClientPool struct {
	shards    []*ShardEntry
	numShards int
	mu        sync.RWMutex

	// Statistics
	totalRequests atomic.Uint64
	shardRequests []atomic.Uint64
}

// ShardEntry represents a single shard with its HTTP client
type ShardEntry struct {
	client              *retryablehttp.Client
	hostCount           atomic.Int64  // Number of unique hosts using this shard
	requestCount        atomic.Uint64 // Total requests through this shard
	createdAt           time.Time
	lastAccess          atomic.Value // time.Time
	maxIdleConnsPerHost int          // Calculated: baseMaxIdle / estimatedHostsPerShard
}

// calculateOptimalShardCount calculates the optimal number of shards based on input size
// Formula: min(256, max(4, sqrt(inputSize) * 2))
func calculateOptimalShardCount(inputSize int) int {
	if inputSize <= 0 {
		// Use default if input size is unknown
		return DefaultShardCount
	}

	// Formula: sqrt(inputSize) * 2, clamped between 4 and 256
	// This scales shards with input size: more inputs = more shards
	optimalShards := int(math.Sqrt(float64(inputSize)) * 2)

	// Ensure minimum of 4 shards for distribution
	if optimalShards < MinShardCount {
		optimalShards = MinShardCount
	}

	// Cap at maximum of 256 shards
	if optimalShards > MaxShardCount {
		optimalShards = MaxShardCount
	}

	return optimalShards
}

// NewShardedClientPool creates a new sharded client pool with automatic shard calculation
func NewShardedClientPool(numShards int, options *types.Options, baseConfig *Configuration, inputSize int) (*ShardedClientPool, error) {
	// If numShards is 0 or negative, calculate optimal number based on input size
	if numShards <= 0 {
		numShards = calculateOptimalShardCount(inputSize)
	} else {
		// Validate provided shard count
		if numShards < MinShardCount {
			numShards = MinShardCount
		}
		if numShards > MaxShardCount {
			numShards = MaxShardCount
		}
	}

	// Base max idle conns per host (from existing logic: 500 when threading enabled)
	baseMaxIdleConnsPerHost := 500
	if baseConfig.Threads == 0 {
		// If no threading, we still want some pooling for sharding
		baseMaxIdleConnsPerHost = 500
	}

	// Use a fixed maxIdleConnsPerHost per shard
	// This provides good connection reuse without needing to estimate host distribution
	// Each shard can handle multiple hosts efficiently
	maxIdleConnsPerHost := baseMaxIdleConnsPerHost

	pool := &ShardedClientPool{
		shards:        make([]*ShardEntry, numShards),
		numShards:     numShards,
		shardRequests: make([]atomic.Uint64, numShards),
	}

	// Initialize all shards with calculated maxIdleConnsPerHost
	for i := 0; i < numShards; i++ {
		client, err := createShardClient(options, baseConfig, maxIdleConnsPerHost)
		if err != nil {
			return nil, fmt.Errorf("failed to create shard %d client: %w", i, err)
		}

		pool.shards[i] = &ShardEntry{
			client:              client,
			createdAt:           time.Now(),
			maxIdleConnsPerHost: maxIdleConnsPerHost,
		}
		pool.shards[i].lastAccess.Store(time.Now())
	}

	gologger.Debug().Msgf("[sharded-pool] Initialized %d HTTP client shards (maxIdleConnsPerHost=%d)",
		numShards, maxIdleConnsPerHost)
	return pool, nil
}

// GetClientForHost returns the HTTP client for the given host based on consistent hashing
// Returns the client and the shard index
func (p *ShardedClientPool) GetClientForHost(host string) (*retryablehttp.Client, int) {
	shardIndex := p.getShardIndex(host)
	shard := p.shards[shardIndex]

	p.shardRequests[shardIndex].Add(1)
	p.totalRequests.Add(1)
	shard.requestCount.Add(1)
	shard.lastAccess.Store(time.Now())

	return shard.client, shardIndex
}

// getShardIndex calculates the shard index for a host using consistent hashing
func (p *ShardedClientPool) getShardIndex(host string) int {
	normalizedHost := normalizeHostForSharding(host)

	hash := fnv.New32a()
	hash.Write([]byte(normalizedHost))

	return int(hash.Sum32()) % p.numShards
}

// normalizeHostForSharding normalizes a host URL for consistent sharding
// Returns host:port format (e.g., "example.com:443")
func normalizeHostForSharding(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		// Fallback: try to extract host:port manually
		return extractHostPortFromStringForReuse(rawURL)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return extractHostPortFromStringForReuse(rawURL)
	}

	port := parsed.Port()
	if port == "" {
		scheme := parsed.Scheme
		if scheme == "" {
			scheme = "http"
		}
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return fmt.Sprintf("%s:%s", hostname, port)
}

// createShardClient creates an HTTP client for a shard with custom maxIdleConnsPerHost
func createShardClient(options *types.Options, config *Configuration, maxIdleConnsPerHost int) (*retryablehttp.Client, error) {
	cfg := config.Clone()
	if cfg.Connection == nil {
		cfg.Connection = &ConnectionConfiguration{}
	}

	// Enable keep-alive for connection reuse
	cfg.Connection.DisableKeepAlive = false

	// Disable cookies for sharded clients to avoid concurrent map writes
	// cookiejar.Jar is not thread-safe and sharded clients are shared across goroutines
	// If cookies are needed, use per-host pooling instead
	cfg.DisableCookie = true

	// Set threading to enable connection pooling
	originalThreads := cfg.Threads
	cfg.Threads = 1 // Minimal threading, sharding provides concurrency

	// Create a modified hash that includes the custom maxIdle value
	// This ensures shards with different maxIdle values get different clients
	hash := hashWithCookieJar(cfg.Hash(), cfg)
	hash = hash + fmt.Sprintf(":maxIdle:%d", maxIdleConnsPerHost)

	// Use wrappedGetWithCustomMaxIdle to create client with custom maxIdleConnsPerHost
	client, err := wrappedGetWithCustomMaxIdle(options, cfg, maxIdleConnsPerHost, hash)
	cfg.Threads = originalThreads

	return client, err
}

// wrappedGetWithCustomMaxIdle creates an HTTP client with a custom maxIdleConnsPerHost value
// This is used for sharding to distribute idle connections evenly per host
func wrappedGetWithCustomMaxIdle(options *types.Options, configuration *Configuration, customMaxIdleConnsPerHost int, hash string) (*retryablehttp.Client, error) {
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}

	// Check if client already exists with this hash
	if client, ok := dialers.HTTPClientPool.Get(hash); ok {
		return client, nil
	}

	// Use standard wrappedGet logic but override maxIdleConnsPerHost
	retryableHttpOptions := retryablehttp.DefaultOptionsSingle
	disableKeepAlives := false
	maxIdleConns := 500
	maxConnsPerHost := customMaxIdleConnsPerHost
	maxIdleConnsPerHost := customMaxIdleConnsPerHost // Use custom value

	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries
	retryableHttpOptions.Timeout = time.Duration(options.Timeout) * time.Second
	if configuration.ResponseHeaderTimeout > 0 && configuration.ResponseHeaderTimeout > retryableHttpOptions.Timeout {
		retryableHttpOptions.Timeout = configuration.ResponseHeaderTimeout
	}

	redirectFlow := configuration.RedirectFlow
	maxRedirects := configuration.MaxRedirects

	if forceMaxRedirects > 0 {
		switch {
		case options.FollowHostRedirects:
			redirectFlow = FollowSameHostRedirect
		default:
			redirectFlow = FollowAllRedirect
		}
		maxRedirects = forceMaxRedirects
	}
	if options.DisableRedirects {
		options.FollowRedirects = false
		options.FollowHostRedirects = false
		redirectFlow = DontFollowRedirect
		maxRedirects = 0
	}

	// Override connection's settings if required
	if configuration.Connection != nil {
		disableKeepAlives = configuration.Connection.DisableKeepAlive
	}

	// Set the base TLS configuration definition
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}

	if options.SNI != "" {
		tlsConfig.ServerName = options.SNI
	}

	// Add the client certificate authentication to the request if it's configured
	var err error
	tlsConfig, err = utils.AddConfiguredClientCertToRequest(tlsConfig, options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create client certificate")
	}

	// responseHeaderTimeout is max timeout for response headers to be read
	responseHeaderTimeout := options.GetTimeouts().HttpResponseHeaderTimeout
	if configuration.ResponseHeaderTimeout != 0 {
		responseHeaderTimeout = configuration.ResponseHeaderTimeout
	}

	if responseHeaderTimeout < retryableHttpOptions.Timeout {
		responseHeaderTimeout = retryableHttpOptions.Timeout
	}

	if configuration.Connection != nil && configuration.Connection.CustomMaxTimeout > 0 {
		responseHeaderTimeout = configuration.Connection.CustomMaxTimeout
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: options.ForceAttemptHTTP2,
		DialContext:       dialers.Fastdialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return dialers.Fastdialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			}
			if options.HasClientCertificates() || options.ForceAttemptHTTP2 {
				return dialers.Fastdialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
			}
			return dialers.Fastdialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost, // Custom value for sharding
		MaxConnsPerHost:       maxConnsPerHost,     // Same value for consistency
		TLSClientConfig:       tlsConfig,
		DisableKeepAlives:     disableKeepAlives,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}

	if options.AliveHttpProxy != "" {
		if proxyURL, err := url.Parse(options.AliveHttpProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if options.AliveSocksProxy != "" {
		socksURL, proxyErr := url.Parse(options.AliveSocksProxy)
		if proxyErr != nil {
			return nil, proxyErr
		}

		dialer, err := proxy.FromURL(socksURL, proxy.Direct)
		if err != nil {
			return nil, err
		}

		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})

		transport.DialContext = dc.DialContext
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dc.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tlsConfig.ServerName == "" {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				tlsConfig.ServerName = host
			}
			return tls.Client(conn, tlsConfig), nil
		}
	}

	// CRITICAL: Never use cookiejars in sharded clients!
	// cookiejar.Jar is not thread-safe and sharded clients are shared across goroutines.
	// This causes "fatal error: concurrent map writes" when multiple goroutines access the same jar.
	// Cookies are disabled for sharded clients (set in createShardClient via cfg.DisableCookie = true)

	httpclient := &http.Client{
		Transport:     transport,
		CheckRedirect: makeCheckRedirectFunc(redirectFlow, maxRedirects),
	}
	if !configuration.NoTimeout {
		httpclient.Timeout = options.GetTimeouts().HttpTimeout
		if configuration.Connection != nil && configuration.Connection.CustomMaxTimeout > 0 {
			httpclient.Timeout = configuration.Connection.CustomMaxTimeout
		}
	}
	client := retryablehttp.NewWithHTTPClient(httpclient, retryableHttpOptions)
	// jar is always nil for sharded clients (thread safety)
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	// Store in pool with modified hash
	// Sharded clients never use cookiejars (disabled for thread safety), so always store in pool
	if err := dialers.HTTPClientPool.Set(hash, client); err != nil {
		return nil, errors.Wrap(err, "could not store client in pool")
	}

	return client, nil
}

// Stats returns statistics about the sharded pool
func (p *ShardedClientPool) Stats() ShardedPoolStats {
	stats := ShardedPoolStats{
		NumShards:     p.numShards,
		TotalRequests: p.totalRequests.Load(),
		ShardStats:    make([]ShardStat, p.numShards),
	}

	for i := 0; i < p.numShards; i++ {
		shard := p.shards[i]
		if shard == nil {
			continue
		}

		lastAccess := time.Time{}
		if la := shard.lastAccess.Load(); la != nil {
			lastAccess = la.(time.Time)
		}

		stats.ShardStats[i] = ShardStat{
			Index:        i,
			RequestCount: shard.requestCount.Load(),
			HostCount:    shard.hostCount.Load(),
			LastAccess:   lastAccess,
		}
	}

	return stats
}

// ShardedPoolStats contains statistics about the sharded pool
type ShardedPoolStats struct {
	NumShards     int
	TotalRequests uint64
	ShardStats    []ShardStat
}

// ShardStat contains statistics for a single shard
type ShardStat struct {
	Index        int
	RequestCount uint64
	HostCount    int64
	LastAccess   time.Time
}

// PrintStats prints statistics about the sharded pool
func (p *ShardedClientPool) PrintStats() {
	stats := p.Stats()
	if stats.TotalRequests == 0 {
		return
	}

	gologger.Info().Msgf("[sharded-pool] HTTP client sharding stats: Shards=%d TotalRequests=%d",
		stats.NumShards, stats.TotalRequests)

	// Print per-shard stats in verbose mode
	// Note: Verbose logging is controlled by gologger's global level
	// We'll always print per-shard stats if there are requests
	for _, shardStat := range stats.ShardStats {
		if shardStat.RequestCount > 0 {
			gologger.Verbose().Msgf("  Shard %d: Requests=%d Hosts=%d LastAccess=%v",
				shardStat.Index, shardStat.RequestCount, shardStat.HostCount,
				shardStat.LastAccess.Round(time.Second))
		}
	}
}

// Close closes the sharded pool (clients are managed by the main HTTPClientPool)
func (p *ShardedClientPool) Close() {
	// Clients are managed by the main HTTPClientPool, no cleanup needed
	// This is just for interface compatibility
}
