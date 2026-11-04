// Package tlsverify gives trackers and exporters an HTTP client that verifies
// TLS certificates, since they send tokens and passwords.
package tlsverify

import (
	"crypto/tls"
	"net/http"
)

// Client returns c, or a copy of c whose transport verifies TLS
// certificates when c can skip verification (the scan client can). The copy
// keeps the proxy and the dialer, so the address policy still applies, but it
// drops a custom TLS dialer, because that dialer can use the scan TLS config.
// So the token never goes over an unverified connection.
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
	if !insecure && t.DialTLSContext == nil && t.DialTLS == nil { //nolint:staticcheck // DialTLS is deprecated but still used
		return c
	}
	verifying := t.Clone()
	verifying.DialTLSContext = nil
	verifying.DialTLS = nil //nolint:staticcheck // DialTLS is deprecated but still used
	if insecure {
		verifying.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	copied := *c
	copied.Transport = verifying
	return &copied
}
