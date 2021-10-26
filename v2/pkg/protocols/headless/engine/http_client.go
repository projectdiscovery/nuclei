package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"golang.org/x/net/proxy"
)

// newhttpClient creates a new http client for headless communication with a timeout
func newhttpClient(options *types.Options) *http.Client {
	dialer := protocolstate.Dialer

	// Set the base TLS configuration definition
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
	}

	// Build the TLS config with the client certificate if it has been configured with the appropriate options.
	// Only one of the options needs to be checked since the validation checks in main.go ensure that all three
	// files are set if any of the client certification configuration options are.
	if len(options.ClientCertFile) > 0 {
		// Load the client certificate using the PEM encoded client certificate and the private key file
		cert, err := tls.LoadX509KeyPair(options.ClientCertFile, options.ClientKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Load the certificate authority PEM certificate into the TLS configuration
		caCert, err := ioutil.ReadFile(options.ClientCAFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		DialContext:         dialer.Dial,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		TLSClientConfig:     tlsConfig,
	}

	if options.ProxyURL != "" {
		if proxyURL, err := url.Parse(options.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if options.ProxySocksURL != "" {
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

	return httpclient
}
