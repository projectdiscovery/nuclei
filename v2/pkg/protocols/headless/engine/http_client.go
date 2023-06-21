package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// newHttpClient creates a new http client for headless communication with a timeout
func newHttpClient(options *types.Options) (*http.Client, error) {
	dialer := protocolstate.Dialer

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
	var err error
	tlsConfig, err = utils.AddConfiguredClientCertToRequest(tlsConfig, options)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: options.ForceAttemptHTTP2,
		DialContext:       dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return dialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			}
			return dialer.DialTLS(ctx, network, addr)
		},
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
		socksURL, proxyErr := url.Parse(types.ProxySocksURL)
		if proxyErr != nil {
			return nil, err
		}
		dialer, err := proxy.FromURL(socksURL, proxy.Direct)
		if err != nil {
			return nil, err
		}

		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		transport.DialContext = dc.DialContext
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
