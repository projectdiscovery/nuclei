package httpclientpool

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/reqx"
)

// reqxTransportParams carries the pooled-transport tuning resolved by Get() so
// the reqx transport can mirror the connection-pool semantics of the historical
// net/http.Transport.
type reqxTransportParams struct {
	disableKeepAlives     bool
	maxIdleConns          int
	maxIdleConnsPerHost   int
	idleConnTimeout       time.Duration
	responseHeaderTimeout time.Duration
}

// newReqxTransport builds the reqx.Transport that backs nuclei's safe HTTP path,
// replacing the net/http.Transport previously constructed inline. fastdialer is
// preserved as the dialer so DNS caching, dialed-IP tracking and network policy
// keep working, while reqx performs TLS and the HTTP exchange. In standard mode
// reqx delegates to an internal net/http.Transport, so connection pooling,
// httptrace (connection-reuse stats), response.TLS and HTTP/2 negotiation all
// keep working as before.
//
// HTTP/2 is only attempted when the user explicitly opts in (-force-attempt-http2),
// matching the historical ForceAttemptHTTP2 behavior; impersonation applies a
// pinned browser profile (TLS + HTTP/2 + matching header values) instead.
func newReqxTransport(dialer *fastdialer.Dialer, options *types.Options, params reqxTransportParams) (*reqx.Transport, error) {
	opts := []reqx.Option{
		reqx.WithDialer(reqx.DialerFunc(dialer.Dial)),
		reqx.WithInsecureSkipVerify(),
		reqx.WithTLSMinVersion(tls.VersionTLS10),
		reqx.WithKeepAlive(!params.disableKeepAlives),
		reqx.WithMaxIdleConns(params.maxIdleConns),
		// reqx couples MaxConnsPerHost and MaxIdleConnsPerHost to a single value;
		// we use the idle-per-host count (threads) so connection reuse matches the
		// historical transport. Per-host concurrency is governed by the scan
		// concurrency manager rather than the transport.
		reqx.WithMaxConnsPerHost(params.maxIdleConnsPerHost),
		reqx.WithIdleConnTimeout(params.idleConnTimeout),
		reqx.WithResponseHeaderTimeout(params.responseHeaderTimeout),
	}

	if options.SNI != "" {
		opts = append(opts, reqx.WithSNI(options.SNI))
	}

	switch {
	case options.TlsImpersonate:
		// Keep-alive and a pinned profile keep TLS, HTTP/2, and default request
		// headers aligned with the impersonated client.
		opts = append(opts,
			reqx.WithKeepAlive(true),
			reqx.WithBrowserProfile(reqx.ProfileChrome131),
		)
	case options.ForceAttemptHTTP2:
		// leave reqx in auto mode so HTTP/2 is negotiated via ALPN
	default:
		opts = append(opts, reqx.WithForceHTTP1())
	}

	// client certificate / custom CA support, mirroring the tls.Config that
	// AddConfiguredClientCertToRequest used to populate on the net/http transport.
	if options.HasClientCertificates() {
		certConfig, err := utils.AddConfiguredClientCertToRequest(&tls.Config{}, options)
		if err != nil {
			return nil, errors.Wrap(err, "could not create client certificate")
		}
		for _, cert := range certConfig.Certificates {
			opts = append(opts, reqx.WithClientCert(cert))
		}
		if certConfig.RootCAs != nil {
			opts = append(opts, reqx.WithRootCAs(certConfig.RootCAs))
		}
	}

	if options.AliveHttpProxy != "" {
		if proxyURL, err := url.Parse(options.AliveHttpProxy); err == nil {
			opts = append(opts, reqx.WithProxyURL(proxyURL))
		}
	} else if options.AliveSocksProxy != "" {
		proxyURL, err := url.Parse(options.AliveSocksProxy)
		if err != nil {
			return nil, err
		}
		opts = append(opts, reqx.WithProxyURL(proxyURL))
	}

	return reqx.NewTransport(opts...), nil
}
