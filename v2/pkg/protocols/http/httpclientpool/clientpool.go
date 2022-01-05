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

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	// Dialer is a copy of the fastdialer from protocolstate
	Dialer *fastdialer.Dialer

	rawHttpClient *rawhttp.Client
	poolMutex     *sync.RWMutex
	normalClient  *retryablehttp.Client
	clientPool    map[string]*retryablehttp.Client
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in the past.
	if normalClient != nil {
		return nil
	}
	poolMutex = &sync.RWMutex{}
	clientPool = make(map[string]*retryablehttp.Client)

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
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Threads contains the threads for the client
	Threads int
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int
	// CookieReuse enables cookie reuse for the http client (cookiejar impl)
	CookieReuse bool
	// FollowRedirects specifies whether to follow redirects
	FollowRedirects bool
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
	builder.WriteString("f")
	builder.WriteString(strconv.FormatBool(c.FollowRedirects))
	builder.WriteString("r")
	builder.WriteString(strconv.FormatBool(c.CookieReuse))
	builder.WriteString("c")
	builder.WriteString(strconv.FormatBool(c.Connection != nil))
	hash := builder.String()
	return hash
}

// HasStandardOptions checks whether the configuration requires custom settings
func (c *Configuration) HasStandardOptions() bool {
	return c.Threads == 0 && c.MaxRedirects == 0 && !c.FollowRedirects && !c.CookieReuse && c.Connection == nil
}

// GetRawHTTP returns the rawhttp request client
func GetRawHTTP(options *types.Options) *rawhttp.Client {
	if rawHttpClient == nil {
		rawHttpOptions := rawhttp.DefaultOptions
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
	poolMutex.RLock()
	if client, ok := clientPool[hash]; ok {
		poolMutex.RUnlock()
		return client, nil
	}
	poolMutex.RUnlock()

	// Multiple Host
	retryableHttpOptions := retryablehttp.DefaultOptionsSpraying
	disableKeepAlives := true
	maxIdleConns := 0
	maxConnsPerHost := 0
	maxIdleConnsPerHost := -1

	if configuration.Threads > 0 {
		// Single host
		retryableHttpOptions = retryablehttp.DefaultOptionsSingle
		disableKeepAlives = false
		maxIdleConnsPerHost = 500
		maxConnsPerHost = 500
	}

	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries
	followRedirects := configuration.FollowRedirects
	maxRedirects := configuration.MaxRedirects

	// override connection's settings if required
	if configuration.Connection != nil {
		disableKeepAlives = configuration.Connection.DisableKeepAlive
	}

	// Set the base TLS configuration definition
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
	}

	// Add the client certificate authentication to the request if it's configured
	tlsConfig, err = utils.AddConfiguredClientCertToRequest(tlsConfig, options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create client certificate")
	}

	transport := &http.Transport{
		DialContext:         Dialer.Dial,
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
		var proxyAuth *proxy.Auth
		socksURL, proxyErr := url.Parse(types.ProxySocksURL)
		if proxyErr == nil {
			proxyAuth = &proxy.Auth{}
			proxyAuth.User = socksURL.User.Username()
			proxyAuth.Password, _ = socksURL.User.Password()
		}
		dialer, proxyErr := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", socksURL.Hostname(), socksURL.Port()), proxyAuth, proxy.Direct)
		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		if proxyErr == nil {
			transport.DialContext = dc.DialContext
		}
	}

	var jar *cookiejar.Jar
	if configuration.CookieReuse {
		if jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}); err != nil {
			return nil, errors.Wrap(err, "could not create cookiejar")
		}
	}

	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
		Timeout:       time.Duration(options.Timeout) * time.Second,
		CheckRedirect: makeCheckRedirectFunc(followRedirects, maxRedirects),
	}, retryableHttpOptions)
	if jar != nil {
		client.HTTPClient.Jar = jar
	}
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	// Only add to client pool if we don't have a cookie jar in place.
	if jar == nil {
		poolMutex.Lock()
		clientPool[hash] = client
		poolMutex.Unlock()
	}
	return client, nil
}

const defaultMaxRedirects = 10

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(followRedirects bool, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}

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
}
