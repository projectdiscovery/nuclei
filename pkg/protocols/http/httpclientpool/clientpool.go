package httpclientpool

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	forceMaxRedirects int
	// MaxResponseHeaderTimeout is the timeout for response headers
	// to be read from the server (this prevents infinite hang started by server if any)
	// Note: this will be overridden temporarily when using @timeout request annotation
	MaxResponseHeaderTimeout = time.Duration(10) * time.Second
	// HttpTimeoutMultiplier is the multiplier for the http timeout
	HttpTimeoutMultiplier = 3
)

// GetHttpTimeout returns the http timeout for the client
func GetHttpTimeout(opts *types.Options) time.Duration {
	return time.Duration(opts.Timeout*HttpTimeoutMultiplier) * time.Second
}

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	if options.Timeout > 10 {
		MaxResponseHeaderTimeout = time.Duration(options.Timeout) * time.Second
	}
	if options.ShouldFollowHTTPRedirects() {
		forceMaxRedirects = options.MaxRedirects
	}
	return nil
}

// ConnectionConfiguration contains the custom configuration options for a connection
type ConnectionConfiguration struct {
	// DisableKeepAlive of the connection
	DisableKeepAlive bool
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

// HasStandardOptions checks whether the configuration requires custom settings
func (c *Configuration) HasStandardOptions() bool {
	return c.Threads == 0 && c.MaxRedirects == 0 && c.RedirectFlow == DontFollowRedirect && c.DisableCookie && c.Connection == nil && !c.NoTimeout && c.ResponseHeaderTimeout == 0
}

// GetRawH returns the rawhttp request client
func GetRaw(options *types.Options) *rawhttp.Client {
	rawHttpOptions := rawhttp.DefaultOptions
	if types.ProxyURL != "" {
		rawHttpOptions.Proxy = types.ProxyURL
	} else if types.ProxySocksURL != "" {
		rawHttpOptions.Proxy = types.ProxySocksURL
	} else if protocolstate.Dialer != nil {
		rawHttpOptions.FastDialer = protocolstate.Dialer
	}
	rawHttpOptions.Timeout = GetHttpTimeout(options)
	return rawhttp.NewClient(rawHttpOptions)
}

// wrappedGet wraps a get operation without normal client check
func Get(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	var err error

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
	responseHeaderTimeout := MaxResponseHeaderTimeout
	if configuration.ResponseHeaderTimeout != 0 {
		responseHeaderTimeout = configuration.ResponseHeaderTimeout
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: options.ForceAttemptHTTP2,
		DialContext:       protocolstate.Dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return protocolstate.Dialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			}
			if options.HasClientCertificates() || options.ForceAttemptHTTP2 {
				return protocolstate.Dialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
			}
			return protocolstate.Dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		TLSClientConfig:       tlsConfig,
		DisableKeepAlives:     disableKeepAlives,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}

	if types.ProxyURL != "" {
		if proxyURL, err := url.Parse(types.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if types.ProxySocksURL != "" {
		socksURL, proxyErr := url.Parse(types.ProxySocksURL)
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
		httpclient.Timeout = GetHttpTimeout(options)
	}
	client := retryablehttp.NewWithHTTPClient(httpclient, retryableHttpOptions)
	if jar != nil {
		client.HTTPClient.Jar = jar
	}
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

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

func checkMaxRedirects(_ *http.Request, via []*http.Request, maxRedirects int) error {
	if maxRedirects == 0 {
		if len(via) > defaultMaxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	if len(via) > maxRedirects {
		return http.ErrUseLastResponse
	}
	return nil
}
