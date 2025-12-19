package httpclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

var (
	forceMaxRedirects int
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	if options.ShouldFollowHTTPRedirects() {
		forceMaxRedirects = options.MaxRedirects
	}

	return nil
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
	if c.Connection != nil && c.Connection.CustomMaxTimeout > 0 {
		builder.WriteString("k")
		builder.WriteString(c.Connection.CustomMaxTimeout.String())
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

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	if configuration.HasStandardOptions() {
		dialers := protocolstate.GetDialersWithId(options.ExecutionId)
		if dialers == nil {
			return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
		}
		return dialers.DefaultHTTPClient, nil
	}

	return wrappedGet(options, configuration)
}

func isMultiThreadWithJar(configuration *Configuration) bool {
	return configuration.Threads > 0 && configuration.Connection != nil && configuration.Connection.HasCookieJar()
}

func hashWithCookieJar(hash string, configuration *Configuration) string {
	if isMultiThreadWithJar(configuration) {
		jar := configuration.Connection.GetCookieJar()
		return hash + fmt.Sprintf("cookieptr%p", jar)
	}
	return hash
}

// wrappedGet wraps a get operation without normal client check
func wrappedGet(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	var err error

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}

	hash := hashWithCookieJar(configuration.Hash(), configuration)
	if client, ok := dialers.HTTPClientPool.Get(hash); ok {
		return client, nil
	}

	// Multiple Host
	retryableHttpOptions := retryablehttp.DefaultOptionsSpraying
	disableKeepAlives := true
	maxIdleConns := 0
	maxConnsPerHost := 0
	maxIdleConnsPerHost := -1
	// do not split given timeout into chunks for retry
	// because this won't work on slow hosts
	retryableHttpOptions.NoAdjustTimeout = true

	// with threading always allow connection reuse
	if configuration.Threads > 0 {
		retryableHttpOptions = retryablehttp.DefaultOptionsSingle
		disableKeepAlives = false
		maxIdleConnsPerHost = 500
		maxConnsPerHost = 500
		maxIdleConns = 500
	}

	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries
	retryableHttpOptions.Timeout = time.Duration(options.Timeout) * time.Second
	if configuration.ResponseHeaderTimeout > 0 && configuration.ResponseHeaderTimeout > retryableHttpOptions.Timeout {
		retryableHttpOptions.Timeout = configuration.ResponseHeaderTimeout
	}
	redirectFlow := configuration.RedirectFlow
	maxRedirects := configuration.MaxRedirects

	if forceMaxRedirects > 0 {
		// by default we enable general redirects following
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

	// override connection's settings if required
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
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
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

	var jar *cookiejar.Jar
	if configuration.Connection != nil && configuration.Connection.HasCookieJar() {
		jar = configuration.Connection.GetCookieJar()
	} else if !configuration.DisableCookie {
		if jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}); err != nil {
			return nil, errors.Wrap(err, "could not create cookiejar")
		}
	}

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
	if jar != nil {
		client.HTTPClient.Jar = jar
	}
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	if jar == nil || isMultiThreadWithJar(configuration) {
		if err := dialers.HTTPClientPool.Set(hash, client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// GetForTarget creates or gets a client for a specific target with per-host connection pooling
func GetForTarget(options *types.Options, configuration *Configuration, targetURL string) (*retryablehttp.Client, error) {
	if !shouldUsePerHostPooling(options, configuration) {
		return Get(options, configuration)
	}

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}

	dialers.Lock()
	if dialers.PerHostHTTPPool == nil {
		dialers.PerHostHTTPPool = NewPerHostClientPool(1024, 5*time.Minute, 30*time.Minute)
	}
	dialers.Unlock()

	pool, ok := dialers.PerHostHTTPPool.(*PerHostClientPool)
	if !ok || pool == nil {
		return Get(options, configuration)
	}

	return pool.GetOrCreate(targetURL, func() (*retryablehttp.Client, error) {
		cfg := configuration.Clone()
		if cfg.Connection == nil {
			cfg.Connection = &ConnectionConfiguration{}
		}
		cfg.Connection.DisableKeepAlive = false

		// Override Threads to force connection pool settings
		// This ensures MaxIdleConnsPerHost and MaxConnsPerHost are set correctly
		originalThreads := cfg.Threads
		cfg.Threads = 1
		client, err := wrappedGet(options, cfg)
		cfg.Threads = originalThreads

		return client, err
	})
}

// shouldUsePerHostPooling determines if per-host pooling should be enabled
func shouldUsePerHostPooling(options *types.Options, config *Configuration) bool {
	// Enable per-host pooling when the flag is set
	return options.PerHostClientPool
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
		dialers.PerHostRateLimitPool = NewPerHostRateLimitPool(1024, 5*time.Minute, 30*time.Minute, options)
	}
	dialers.Unlock()

	pool, ok := dialers.PerHostRateLimitPool.(*PerHostRateLimitPool)
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

	pool, ok := dialers.PerHostRateLimitPool.(*PerHostRateLimitPool)
	if !ok || pool == nil {
		return
	}

	pool.RecordRequest(hostname)
}

type RedirectFlow uint8

const (
	DontFollowRedirect RedirectFlow = iota
	FollowSameHostRedirect
	FollowAllRedirect
)

const defaultMaxRedirects = 10

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(redirectType RedirectFlow, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		switch redirectType {
		case DontFollowRedirect:
			return http.ErrUseLastResponse
		case FollowSameHostRedirect:
			var newHost = req.URL.Host
			var oldHost = via[0].Host
			if oldHost == "" {
				oldHost = via[0].URL.Host
			}
			if newHost != oldHost {
				// Tell the http client to not follow redirect
				return http.ErrUseLastResponse
			}
			return checkMaxRedirects(req, via, maxRedirects)
		case FollowAllRedirect:
			return checkMaxRedirects(req, via, maxRedirects)
		}
		return nil
	}
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
