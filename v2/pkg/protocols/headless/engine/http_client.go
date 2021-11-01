package engine

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// newhttpClient creates a new http client for headless communication with a timeout
func newhttpClient(options *types.Options) *http.Client {
	dialer := protocolstate.Dialer
	transport := &http.Transport{
		DialContext:         dialer.Dial,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
	}
	var proxyenv = os.Getenv(types.HTTP_PROXY_ENV)
	if proxyenv != "" {
		if proxyURL, err := url.Parse(proxyenv); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	// if options.ProxyURL != "" {
	// 	if proxyURL, err := url.Parse(options.ProxyURL); err == nil {
	// 		transport.Proxy = http.ProxyURL(proxyURL)
	// 	}
	// }

	return &http.Client{Transport: transport, Timeout: time.Duration(options.Timeout*3) * time.Second}
}
