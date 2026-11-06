// Package tlsverify gives trackers and exporters an HTTP client that verifies
// TLS certificates, since they send tokens and passwords.
package tlsverify

import (
	"crypto/tls"
	"errors"
	"net/http"
)

// errTLSDialerOnly is returned when a transport dials HTTPS only through a
// custom TLS dialer: dropping that dialer would also drop its route or address
// policy, so the copy refuses requests instead.
var errTLSDialerOnly = errors.New("tlsverify: the transport has a custom TLS dialer and no DialContext, so certificate verification cannot be enforced")

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errTLSDialerOnly
}

// Client returns c, or a copy of c whose transport verifies TLS certificates
// when c can skip verification (the scan client can). The copy keeps the proxy
// and the dialer, so the address policy still applies, but it drops a custom
// TLS dialer, because that dialer can use the scan TLS config. So the token
// never goes over an unverified connection.
//
// A transport with an Unwrap() http.RoundTripper method declares that its
// RoundTrip only observes or caches requests and enforces no policy; the copy
// uses the unwrapped transport. Other transports are returned unchanged.
func Client(c *http.Client) *http.Client {
	rt := c.Transport
	for {
		u, ok := rt.(interface{ Unwrap() http.RoundTripper })
		if !ok {
			break
		}
		rt = u.Unwrap()
	}
	t, ok := rt.(*http.Transport)
	if !ok {
		return c
	}
	insecure := t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify
	tlsDialer := t.DialTLSContext != nil || t.DialTLS != nil //nolint:staticcheck // DialTLS is deprecated but still used
	if !insecure && !tlsDialer {
		return c
	}
	copied := *c
	if tlsDialer && t.DialContext == nil && t.Dial == nil { //nolint:staticcheck // Dial is deprecated but still used
		copied.Transport = refusingTransport{}
		return &copied
	}
	verifying := t.Clone()
	verifying.DialTLSContext = nil
	verifying.DialTLS = nil //nolint:staticcheck // DialTLS is deprecated but still used
	if insecure {
		// Keep the caller's roots, client certificates and checks; the server
		// name of the scan config belongs to a scan target, not to this host.
		verifying.TLSClientConfig.InsecureSkipVerify = false
		verifying.TLSClientConfig.ServerName = ""
		if verifying.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			verifying.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	copied.Transport = verifying
	return &copied
}
