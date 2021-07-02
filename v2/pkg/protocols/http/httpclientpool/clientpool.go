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
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

var (
	// Dialer is a copy of the fastdialer from protocolstate
	Dialer *fastdialer.Dialer

	rawhttpClient *rawhttp.Client
	poolMutex     *sync.RWMutex
	normalClient  *retryablehttp.Client
	clientPool    map[string]*retryablehttp.Client
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in past.
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
	hash := builder.String()
	return hash
}

// GetRawHTTP returns the rawhttp request client
func GetRawHTTP(options *types.Options) *rawhttp.Client {
	if rawhttpClient == nil {
		rawhttpOptions := rawhttp.DefaultOptions
		rawhttpOptions.Timeout = time.Duration(options.Timeout) * time.Second
		rawhttpClient = rawhttp.NewClient(rawhttpOptions)
	}
	return rawhttpClient
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	if configuration.Threads == 0 && configuration.MaxRedirects == 0 && !configuration.FollowRedirects && !configuration.CookieReuse {
		return normalClient, nil
	}
	return wrappedGet(options, configuration)
}

// wrappedGet wraps a get operation without normal client check
func wrappedGet(options *types.Options, configuration *Configuration) (*retryablehttp.Client, error) {
	var proxyURL *url.URL
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

	if options.ProxyURL != "" {
		proxyURL, err = url.Parse(options.ProxyURL)
	}
	if err != nil {
		return nil, err
	}

	// Multiple Host
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	disableKeepAlives := true
	maxIdleConns := 0
	maxConnsPerHost := 0
	maxIdleConnsPerHost := -1

	if configuration.Threads > 0 {
		// Single host
		retryablehttpOptions = retryablehttp.DefaultOptionsSingle
		disableKeepAlives = false
		maxIdleConnsPerHost = 500
		maxConnsPerHost = 500
	}

	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = options.Retries
	followRedirects := configuration.FollowRedirects
	maxRedirects := configuration.MaxRedirects

	transport := &http.Transport{
		DialContext:         Dialer.Dial,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: disableKeepAlives,
	}

	// Attempts to overwrite the dial function with the socks proxied version
	if options.ProxySocksURL != "" {
		var proxyAuth *proxy.Auth

		socksURL, proxyErr := url.Parse(options.ProxySocksURL)
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
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
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
	}, retryablehttpOptions)
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
