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
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	rawHttpClient     *rawhttp.Client
	rawHttpClientOnce sync.Once
	forceMaxRedirects int
	normalClient      *retryablehttp.Client
	clientPool        *mapsutil.SyncLockMap[string, *retryablehttp.Client]
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in the past.
	if normalClient != nil {
		return nil
	}
	if options.ShouldFollowHTTPRedirects() {
		forceMaxRedirects = options.MaxRedirects
	}
	clientPool = &mapsutil.SyncLockMap[string, *retryablehttp.Client]{
		Map: make(mapsutil.Map[string, *retryablehttp.Client]),
	}

	client, err := wrappedGet(options, &Configuration{})
	if err != nil {
		return err
	}
	normalClient = client
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
	rawHttpClientOnce.Do(func() {
		rawHttpOptions := rawhttp.DefaultOptions
		if options.Options.AliveHttpProxy != "" {
			rawHttpOptions.Proxy = options.Options.AliveHttpProxy
		} else if options.Options.AliveSocksProxy != "" {
			rawHttpOptions.Proxy = options.Options.AliveSocksProxy
		} else if protocolstate.Dialer != nil {
			rawHttpOptions.FastDialer = protocolstate.Dialer
		}
		rawHttpOptions.Timeout = options.Options.GetTimeouts().HttpTimeout
		rawHttpClient = rawhttp.NewClient(rawHttpOptions)
	})
	return rawHttpClient
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	if configuration.HasStandardOptions() {
		return normalClient, nil
	}
	return wrappedGet(options, configuration)
}

// wrappedGet wraps a get operation without normal client check
func wrappedGet(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	var err error

	hash := configuration.Hash()
	if client, ok := clientPool.Get(hash); ok {
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

	if configuration.Threads > 0 || options.ScanStrategy == scanstrategy.HostSpray.String() {
		// Single host
		retryableHttpOptions = retryablehttp.DefaultOptionsSingle
		disableKeepAlives = false
		maxIdleConnsPerHost = 500
		maxConnsPerHost = 500
	}

	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries
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
	if configuration.Connection != nil && configuration.Connection.CustomMaxTimeout > 0 {
		responseHeaderTimeout = configuration.Connection.CustomMaxTimeout
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: options.ForceAttemptHTTP2,
		DialContext:       protocolstate.GetDialer().Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return protocolstate.Dialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			}
			if options.HasClientCertificates() || options.ForceAttemptHTTP2 {
				return protocolstate.Dialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
			}
			return protocolstate.GetDialer().DialTLS(ctx, network, addr)
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

	// Only add to client pool if we don't have a cookie jar in place.
	if jar == nil {
		if err := clientPool.Set(hash, client); err != nil {
			return nil, err
		}
	}
	return client, nil
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
