package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"

	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// newHttpClient creates a new http client for headless communication with a timeout
func newHttpClient(options *types.Options) (*http.Client, error) {
	dialer := protocolstate.Dialer

	// Set the base TLS configuration definition
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
	}

	// Add the client certificate authentication to the request if it's configured
	var err error
	tlsConfig, err = utils.AddConfiguredClientCertToRequest(tlsConfig, options)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext:         dialer.Dial,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		TLSClientConfig:     tlsConfig,
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

	jar, _ := cookiejar.New(nil)

	httpclient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(options.Timeout*3) * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// the browser should follow redirects not us
			return http.ErrUseLastResponse
		},
	}

	return httpclient, nil
}
