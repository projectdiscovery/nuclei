package httpclientpool

import (
	"context"
	"crypto/tls"
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

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types/scanstrategy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	// Dialer is a copy of the fastdialer from protocolstate
	Dialer *fastdialer.Dialer

	rawHttpClient     *rawhttp.Client
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
	// CookieReuse enables cookie reuse for the http client (cookiejar impl)
	CookieReuse bool
	// FollowRedirects specifies the redirects flow
	RedirectFlow RedirectFlow
	// Connection defines custom connection configuration
	Connection *ConnectionConfiguration
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
	builder.WriteString(strconv.FormatBool(c.CookieReuse))
	builder.WriteString("c")
	builder.WriteString(strconv.FormatBool(c.Connection != nil))
	hash := builder.String()
	return hash
}

// HasStandardOptions checks whether the configuration requires custom settings
func (c *Configuration) HasStandardOptions() bool {
	return c.Threads == 0 && c.MaxRedirects == 0 && c.RedirectFlow == DontFollowRedirect && !c.CookieReuse && c.Connection == nil && !c.NoTimeout
}

// GetRawHTTP returns the rawhttp request client
func GetRawHTTP(options *types.Options) *rawhttp.Client {
	if rawHttpClient == nil {
		rawHttpOptions := rawhttp.DefaultOptions
		if types.ProxyURL != "" {
			rawHttpOptions.Proxy = types.ProxyURL
		} else if types.ProxySocksURL != "" {
			rawHttpOptions.Proxy = types.ProxySocksURL
		} else if Dialer != nil {
			rawHttpOptions.FastDialer = Dialer
		}
		rawHttpOptions.Timeout = time.Duration(options.Timeout) * time.Second
		rawHttpClient = rawhttp.NewClient(rawHttpOptions)
	}
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

	if Dialer == nil {
		Dialer = protocolstate.Dialer
	}

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

	transport := &http.Transport{
		ForceAttemptHTTP2: options.ForceAttemptHTTP2,
		DialContext:       Dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.HasClientCertificates() {
				return Dialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
			}
			if options.TlsImpersonate {
				return Dialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			}
			return Dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   disableKeepAlives,
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
	} else if configuration.CookieReuse {
		if jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}); err != nil {
			return nil, errors.Wrap(err, "could not create cookiejar")
		}
	}

	httpclient := &http.Client{
		Transport:     transport,
		CheckRedirect: makeCheckRedirectFunc(redirectFlow, maxRedirects),
	}
	if !configuration.NoTimeout {
		httpclient.Timeout = time.Duration(options.Timeout) * time.Second
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
	return nil
}
