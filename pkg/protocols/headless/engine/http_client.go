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

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// newHttpClient creates a new http client for headless communication with a timeout
func newHttpClient(options *types.Options) (*http.Client, error) {
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
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
		return nil, err
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
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		TLSClientConfig:     tlsConfig,
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
	}

	var roundTripper http.RoundTripper = transport

	// TLS impersonation via utls advertises h2 in ALPN to mimic a real browser.
	// Since utls returns *utls.UConn (not *tls.Conn), Go's http.Transport can't
	// detect the negotiated protocol and tries HTTP/1.x on an h2 connection,
	// causing "malformed HTTP response" errors. We use http2.Transport directly
	// with utls dialing to properly handle h2 connections (see #6360).
	if options.TlsImpersonate {
		roundTripper = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialers.Fastdialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
			},
			TLSClientConfig:    tlsConfig,
			AllowHTTP:          false,
			DisableCompression: false,
		}
	}

	jar, _ := cookiejar.New(nil)

	httpclient := &http.Client{
		Transport: roundTripper,
		Timeout:   time.Duration(options.Timeout*3) * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// the browser should follow redirects not us
			return http.ErrUseLastResponse
		},
	}

	return httpclient, nil
}

