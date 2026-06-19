package httpclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

var connStats ConnectionStats

// perHostConnStats buckets connection reuse per normalized host alongside the
// global connStats counters. It is populated from the same httptrace.GotConn
// hook in connTrackingTransport, so per-host visibility adds no extra trace
// plumbing or second round-trip wrapper. Reads are lock-free (sync.Map) and
// each bucket uses atomics, keeping the hot path cheap.
var perHostConnStats sync.Map // map[string]*hostConnStat

// ConnectionStats tracks HTTP connection reuse across the scan.
type ConnectionStats struct {
	New    atomic.Int64
	Reused atomic.Int64
}

// hostConnStat holds per-host new/reused connection counters.
type hostConnStat struct {
	New    atomic.Int64
	Reused atomic.Int64
}

// PerHostConnStat is a point-in-time snapshot of a single host's connection reuse.
type PerHostConnStat struct {
	Host   string
	New    int64
	Reused int64
}

// recordHostConn records a connection event for a single host. It is called
// from the global GotConn hook so the global and per-host views stay in sync.
func recordHostConn(host string, reused bool) {
	if host == "" {
		return
	}
	v, ok := perHostConnStats.Load(host)
	if !ok {
		v, _ = perHostConnStats.LoadOrStore(host, &hostConnStat{})
	}
	hs := v.(*hostConnStat)
	if reused {
		hs.Reused.Add(1)
	} else {
		hs.New.Add(1)
	}
}

// GetPerHostConnectionStats returns a snapshot of per-host connection reuse.
func GetPerHostConnectionStats() []PerHostConnStat {
	var out []PerHostConnStat
	perHostConnStats.Range(func(k, v any) bool {
		hs := v.(*hostConnStat)
		out = append(out, PerHostConnStat{
			Host:   k.(string),
			New:    hs.New.Load(),
			Reused: hs.Reused.Load(),
		})
		return true
	})
	return out
}

// GetConnectionStats returns the current connection statistics.
//
// NOTE: counters are package-global and accumulate across in-process scans.
// Callers running multiple SDK/embedded executions in the same process should
// invoke ResetConnectionStats() at the start of each run to avoid reporting
// totals that mix results from earlier runs.
func GetConnectionStats() (newConns, reused int64) {
	return connStats.New.Load(), connStats.Reused.Load()
}

// ResetConnectionStats clears the package-global new/reused connection counters
// (both the global totals and the per-host breakdown). Intended to be called at
// the start of an execution to scope the metrics to a single run.
func ResetConnectionStats() {
	connStats.New.Store(0)
	connStats.Reused.Store(0)
	perHostConnStats.Range(func(k, _ any) bool {
		perHostConnStats.Delete(k)
		return true
	})
}

// connTrackingTransport wraps an http.RoundTripper to track connection reuse
// via httptrace. Every request gets a GotConn callback that increments the
// appropriate counter before delegating to the underlying transport.
type connTrackingTransport struct {
	base http.RoundTripper
}

func (t *connTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Compute the host key once (URL is already parsed) so the GotConn hook can
	// update both the global counters and the per-host bucket from one trace.
	host := normalizeHost(req.URL)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				connStats.Reused.Add(1)
			} else {
				connStats.New.Add(1)
			}
			recordHostConn(host, info.Reused)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	return t.base.RoundTrip(req)
}

func (t *connTrackingTransport) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if ci, ok := t.base.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

// ConnectionConfiguration contains the custom configuration options for a connection
type ConnectionConfiguration struct {
	// DisableKeepAlive of the connection
	DisableKeepAlive bool
	// CustomMaxTimeout is the custom timeout for the connection
	// This overrides all other timeouts and is used for accurate time based fuzzing.
	CustomMaxTimeout time.Duration
	cookiejar        *cookiejar.Jar
	mu               sync.RWMutex
}

func (cc *ConnectionConfiguration) SetCookieJar(cookiejar *cookiejar.Jar) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cookiejar = cookiejar
}

func (cc *ConnectionConfiguration) GetCookieJar() *cookiejar.Jar {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	return cc.cookiejar
}

func (cc *ConnectionConfiguration) HasCookieJar() bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	return cc.cookiejar != nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Threads contains the threads for the client
	Threads int
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int
	// NoTimeout disables http request timeout for context based usage
	NoTimeout bool
	// DisableCookie disables cookie reuse for the http client (cookiejar impl)
	DisableCookie bool
	// FollowRedirects specifies the redirects flow
	RedirectFlow RedirectFlow
	// Connection defines custom connection configuration
	Connection *ConnectionConfiguration
	// ResponseHeaderTimeout is the timeout for response body to be read from the server
	ResponseHeaderTimeout time.Duration
}

func (c *Configuration) Clone() *Configuration {
	clone := *c
	if c.Connection != nil {
		cloneConnection := &ConnectionConfiguration{
			DisableKeepAlive: c.Connection.DisableKeepAlive,
			CustomMaxTimeout: c.Connection.CustomMaxTimeout,
		}
		if c.Connection.HasCookieJar() {
			cookiejar := *c.Connection.GetCookieJar()
			cloneConnection.SetCookieJar(&cookiejar)
		}
		clone.Connection = cloneConnection
	}

	return &clone
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() string {
	builder := &strings.Builder{}
	builder.Grow(16)
	builder.WriteString("t")
	builder.WriteString(strconv.Itoa(c.Threads))
	builder.WriteString("m")
	builder.WriteString(strconv.Itoa(c.MaxRedirects))
	builder.WriteString("n")
	builder.WriteString(strconv.FormatBool(c.NoTimeout))
	builder.WriteString("f")
	builder.WriteString(strconv.Itoa(int(c.RedirectFlow)))
	builder.WriteString("r")
	builder.WriteString(strconv.FormatBool(c.DisableCookie))
	builder.WriteString("c")
	builder.WriteString(strconv.FormatBool(c.Connection != nil))
	if c.Connection != nil {
		// keep-alive flag must participate in the hash; otherwise two
		// configurations differing only in DisableKeepAlive will collide and
		// return a cached client with the wrong connection-reuse semantics.
		builder.WriteString("d")
		builder.WriteString(strconv.FormatBool(c.Connection.DisableKeepAlive))
		if c.Connection.CustomMaxTimeout > 0 {
			builder.WriteString("k")
			builder.WriteString(c.Connection.CustomMaxTimeout.String())
		}
	}
	builder.WriteString("r")
	builder.WriteString(strconv.FormatInt(int64(c.ResponseHeaderTimeout.Seconds()), 10))
	hash := builder.String()
	return hash
}

// HasStandardOptions checks whether the configuration requires custom settings
func (c *Configuration) HasStandardOptions() bool {
	return c.Threads == 0 && c.MaxRedirects == 0 && c.RedirectFlow == DontFollowRedirect && c.DisableCookie && c.Connection == nil && !c.NoTimeout && c.ResponseHeaderTimeout == 0
}

// GetRawHTTP returns the rawhttp request client
func GetRawHTTP(options *protocols.ExecutorOptions) *rawhttp.Client {
	dialers := protocolstate.GetDialersWithId(options.Options.ExecutionId)
	if dialers == nil {
		panic("dialers not initialized for execution id: " + options.Options.ExecutionId)
	}

	// Lock the dialers to avoid a race when setting RawHTTPClient
	dialers.Lock()
	defer dialers.Unlock()

	if dialers.RawHTTPClient != nil {
		return dialers.RawHTTPClient
	}

	rawHttpOptionsCopy := *rawhttp.DefaultOptions
	if options.Options.AliveHttpProxy != "" {
		rawHttpOptionsCopy.Proxy = options.Options.AliveHttpProxy
	} else if options.Options.AliveSocksProxy != "" {
		rawHttpOptionsCopy.Proxy = options.Options.AliveSocksProxy
	} else if dialers.Fastdialer != nil {
		rawHttpOptionsCopy.FastDialer = dialers.Fastdialer
	}
	rawHttpOptionsCopy.Timeout = options.Options.GetTimeouts().HttpTimeout
	dialers.RawHTTPClient = rawhttp.NewClient(&rawHttpOptionsCopy)
	return dialers.RawHTTPClient
}

// Get creates or gets a client for the protocol based on custom configuration.
// The host parameter scopes the client to a specific target, enabling per-host
// connection reuse with keep-alive. Pass an empty string for non-scanning uses.
func Get(options *types.Options, configuration *Configuration, host string) (*retryablehttp.Client, error) {
	return wrappedGet(options, configuration, host)
}

// wrappedGet wraps a get operation without normal client check
func wrappedGet(options *types.Options, configuration *Configuration, host string) (*retryablehttp.Client, error) {
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}
	pool := dialers.HTTPClientPool

	// Explicit per-request cookie jars always bypass the client cache so
	// session state is never leaked into the shared pool; they still share
	// the pooled per-host transport below.
	hasExplicitJar := configuration.Connection != nil && configuration.Connection.HasCookieJar()

	clientKey := configuration.Hash()
	if host != "" {
		clientKey += ":" + host
	}

	// Fast path: lock-free cache hit.
	if !hasExplicitJar {
		if client, ok := pool.GetClient(clientKey); ok {
			return client, nil
		}
	}

	// Each client is scoped to a single host, so we optimize for connection
	// reuse: keep-alive always on, small idle pool, and an idle timeout that
	// lets the transport reclaim unused connections automatically.
	retryableHttpOptions := retryablehttp.DefaultOptionsSingle
	retryableHttpOptions.NoAdjustTimeout = true
	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries
	retryableHttpOptions.Timeout = time.Duration(options.Timeout) * time.Second
	if configuration.ResponseHeaderTimeout > 0 && configuration.ResponseHeaderTimeout > retryableHttpOptions.Timeout {
		retryableHttpOptions.Timeout = configuration.ResponseHeaderTimeout
	}

	maxIdleConns := 4
	maxIdleConnsPerHost := 4
	maxConnsPerHost := 0 // unlimited by default; the SPM handler controls concurrency
	if configuration.Threads > 0 {
		maxIdleConnsPerHost = configuration.Threads
		maxIdleConns = configuration.Threads
	}

	disableKeepAlives := configuration.Connection != nil && configuration.Connection.DisableKeepAlive

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

	// Transports are pooled separately from clients: only parameters that
	// actually live on http.Transport participate in the key, so clients
	// that differ in client-level settings (redirect policy, cookies,
	// timeout) still share a single connection pool per host.
	transportKey := transportHash(host, disableKeepAlives, maxIdleConns, maxIdleConnsPerHost, maxConnsPerHost, responseHeaderTimeout)

	createTransport := func() (http.RoundTripper, error) {
		// Set the base TLS configuration definition
		tlsConfig := &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ClientSessionCache: sharedTLSSessionCache,
		}

		if options.SNI != "" {
			tlsConfig.ServerName = options.SNI
		}

		tlsConfig, err := utils.AddConfiguredClientCertToRequest(tlsConfig, options)
		if err != nil {
			return nil, errors.Wrap(err, "could not create client certificate")
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
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
			MaxConnsPerHost:       maxConnsPerHost,
			TLSClientConfig:       tlsConfig,
			DisableKeepAlives:     disableKeepAlives,
			IdleConnTimeout:       30 * time.Second,
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
				// upgrade proxy connection to tls
				conn, err := dc.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if tlsConfig.ServerName == "" {
					// addr should be in form of host:port already set from canonicalAddr
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					tlsConfig.ServerName = host
				}
				return tls.Client(conn, tlsConfig), nil
			}
		}

		return &connTrackingTransport{base: transport}, nil
	}

	redirectFlow := configuration.RedirectFlow
	maxRedirects := configuration.MaxRedirects

	if options.ShouldFollowHTTPRedirects() {
		switch {
		case options.FollowHostRedirects:
			redirectFlow = FollowSameHostRedirect
		default:
			redirectFlow = FollowAllRedirect
		}
		if options.MaxRedirects > 0 {
			maxRedirects = options.MaxRedirects
		}
	}
	if options.DisableRedirects {
		options.FollowRedirects = false
		options.FollowHostRedirects = false
		redirectFlow = DontFollowRedirect
		maxRedirects = 0
	}

	createClient := func(rt http.RoundTripper) (*retryablehttp.Client, error) {
		// Each per-host client gets its own default cookie jar. This is safe
		// because cookies are domain-scoped per RFC 6265, and same-host iterations
		// (workflows, multi-step templates) hit the same cached client so cookies
		// are retained across requests. Explicit jars from input.CookieJar bypass
		// the client cache for full isolation.
		var jar *cookiejar.Jar
		if hasExplicitJar {
			jar = configuration.Connection.GetCookieJar()
		} else if !configuration.DisableCookie {
			var err error
			if jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}); err != nil {
				return nil, errors.Wrap(err, "could not create cookiejar")
			}
		}

		httpclient := &http.Client{
			Transport:     rt,
			CheckRedirect: makeCheckRedirectFunc(redirectFlow, maxRedirects),
		}
		if !configuration.NoTimeout {
			httpclient.Timeout = options.GetTimeouts().HttpTimeout
			if configuration.Connection != nil && configuration.Connection.CustomMaxTimeout > 0 {
				httpclient.Timeout = configuration.Connection.CustomMaxTimeout
			}
		}
		client := retryablehttp.NewWithHTTPClient(httpclient, retryableHttpOptions)
		if jar != nil {
			client.HTTPClient.Jar = jar
		}
		client.CheckRetry = retryablehttp.HostSprayRetryPolicy()
		return client, nil
	}

	if hasExplicitJar {
		rt, err := pool.GetOrCreateTransport(transportKey, createTransport)
		if err != nil {
			return nil, err
		}
		return createClient(rt)
	}
	// Singleflight creation: concurrent first requests to the same host build
	// exactly one client instead of racing Get/Set and orphaning transports.
	return pool.GetOrCreateClient(clientKey, transportKey, createTransport, createClient)
}

// sharedTLSSessionCache is shared by all pooled transports so TLS session
// resumption survives transport eviction/re-creation, and a single bounded
// LRU replaces a 128-entry cache per host client.
var sharedTLSSessionCache = tls.NewLRUClientSessionCache(2048)

// transportHash identifies a shareable transport. Only parameters that live
// on http.Transport participate; everything else (redirects, cookie jars,
// client timeouts) is layered on top by the per-configuration client.
func transportHash(host string, disableKeepAlives bool, maxIdleConns, maxIdleConnsPerHost, maxConnsPerHost int, responseHeaderTimeout time.Duration) string {
	builder := &strings.Builder{}
	builder.Grow(len(host) + 32)
	builder.WriteString(host)
	builder.WriteString("|ka")
	builder.WriteString(strconv.FormatBool(!disableKeepAlives))
	builder.WriteString("|i")
	builder.WriteString(strconv.Itoa(maxIdleConns))
	builder.WriteString("|ih")
	builder.WriteString(strconv.Itoa(maxIdleConnsPerHost))
	builder.WriteString("|ch")
	builder.WriteString(strconv.Itoa(maxConnsPerHost))
	builder.WriteString("|rht")
	builder.WriteString(strconv.FormatInt(int64(responseHeaderTimeout), 10))
	return builder.String()
}

type RedirectFlow uint8

const (
	DontFollowRedirect RedirectFlow = iota
	FollowSameHostRedirect
	FollowAllRedirect
	FollowSameSchemeRedirect
)

const defaultMaxRedirects = 10

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(redirectType RedirectFlow, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		switch redirectType {
		case DontFollowRedirect:
			return http.ErrUseLastResponse
		case FollowSameHostRedirect:
			var newHost = normalizeHost(req.URL)
			var oldHost string
			if via[0].Host != "" {
				oldHost = normalizeHost(&url.URL{Scheme: via[0].URL.Scheme, Host: via[0].Host})
			} else {
				oldHost = normalizeHost(via[0].URL)
			}
			if newHost != oldHost {
				return http.ErrUseLastResponse
			}
			return checkMaxRedirects(req, via, maxRedirects)
		case FollowAllRedirect:
			return checkMaxRedirects(req, via, maxRedirects)
		case FollowSameSchemeRedirect:
			previousScheme := via[len(via)-1].URL.Scheme
			if req.URL.Scheme != previousScheme {
				return http.ErrUseLastResponse
			}
			return checkMaxRedirects(req, via, maxRedirects)
		}
		return nil
	}
}

// normalizeHost strips default ports (80 for http, 443 for https) from
// the URL host so that "example.com:80" and "example.com" compare equal.
func normalizeHost(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return u.Host
}

func checkMaxRedirects(req *http.Request, via []*http.Request, maxRedirects int) error {
	if maxRedirects == 0 {
		if len(via) > defaultMaxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	if len(via) > maxRedirects {
		return http.ErrUseLastResponse
	}

	// NOTE(dwisiswant0): rebuild request URL. See #5900.
	if u := req.URL.String(); !isURLEncoded(u) {
		parsed, err := urlutil.Parse(u)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRebuildURL, err)
		}

		req.URL = parsed.URL
	}

	return nil
}

// isURLEncoded is an helper function to check if the URL is already encoded
//
// NOTE(dwisiswant0): shall we move this under `projectdiscovery/utils/urlutil`?
func isURLEncoded(s string) bool {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		// If decoding fails, it may indicate a malformed URL/invalid encoding.
		return false
	}

	return decoded != s
}

// GetPerHostRateLimiter gets or creates a rate limiter for a specific host
// Returns nil if per-host rate limiting is not enabled
func GetPerHostRateLimiter(options *types.Options, hostname string) (*ratelimit.Limiter, error) {
	if !options.PerHostRateLimit {
		return nil, nil
	}

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}

	dialers.Lock()
	if dialers.PerHostRateLimitPool == nil {
		// Keep entries for the entire scan duration - no TTL-based eviction during scan
		// so all hosts are tracked throughout the entire scan, even for very long scans
		dialers.PerHostRateLimitPool = NewPerHostRateLimitPool(1024, 24*time.Hour, 24*time.Hour, options)
	}
	poolAny := dialers.PerHostRateLimitPool
	dialers.Unlock()

	pool, ok := poolAny.(*PerHostRateLimitPool)
	if !ok || pool == nil {
		return nil, nil
	}

	return pool.GetOrCreate(hostname)
}

// RecordPerHostRateLimitRequest records a request for pps stats calculation
func RecordPerHostRateLimitRequest(options *types.Options, hostname string) {
	if !options.PerHostRateLimit || hostname == "" {
		return
	}

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return
	}

	dialers.Lock()
	poolAny := dialers.PerHostRateLimitPool
	dialers.Unlock()

	pool, ok := poolAny.(*PerHostRateLimitPool)
	if !ok || pool == nil {
		return
	}

	pool.RecordRequest(hostname)
}

// GetHTTPToHTTPSPortTracker gets or creates the HTTP-to-HTTPS port tracker
func GetHTTPToHTTPSPortTracker(options *types.Options) *HTTPToHTTPSPortTracker {
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil
	}

	dialers.Lock()
	if dialers.HTTPToHTTPSPortTracker == nil {
		dialers.HTTPToHTTPSPortTracker = NewHTTPToHTTPSPortTracker()
	}
	trackerAny := dialers.HTTPToHTTPSPortTracker
	dialers.Unlock()

	tracker, ok := trackerAny.(*HTTPToHTTPSPortTracker)
	if !ok || tracker == nil {
		return nil
	}

	return tracker
}

// RecordHTTPToHTTPSPortMismatch records that a host:port requires HTTPS
func RecordHTTPToHTTPSPortMismatch(options *types.Options, hostname string) {
	if hostname == "" {
		return
	}

	tracker := GetHTTPToHTTPSPortTracker(options)
	if tracker == nil {
		return
	}

	tracker.RecordHTTPToHTTPSPort(hostname)
}
