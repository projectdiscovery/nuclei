package tlsverify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The scan client can skip TLS verification; the tracker must not send the
// token over such a connection, and must not change the caller's client.
func TestClientTurnsOnTLSVerification(t *testing.T) {
	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	caller := &http.Client{Transport: insecure}

	got := Client(caller)
	gotTransport, ok := got.Transport.(*http.Transport)
	require.True(t, ok)
	require.False(t, gotTransport.TLSClientConfig.InsecureSkipVerify)
	require.True(t, insecure.TLSClientConfig.InsecureSkipVerify, "the caller's transport changed")

	secure := &http.Client{Transport: &http.Transport{}}
	require.Same(t, secure, Client(secure))
}

func TestClientKeepsCallerTLSSettings(t *testing.T) {
	pinned := func(tls.ConnectionState) error { return nil }
	insecure := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("scan dialer") },
		DialContext:    (&net.Dialer{}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "scan-target.example",
			MinVersion:         tls.VersionTLS10,
			RootCAs:            x509.NewCertPool(),
			VerifyConnection:   pinned,
		},
	}
	got := Client(&http.Client{Transport: insecure}).Transport.(*http.Transport)
	require.Nil(t, got.DialTLSContext)
	require.NotNil(t, got.DialContext)
	cfg := got.TLSClientConfig
	require.False(t, cfg.InsecureSkipVerify)
	require.Empty(t, cfg.ServerName)
	require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	require.Same(t, insecure.TLSClientConfig.RootCAs, cfg.RootCAs)
	require.NotNil(t, cfg.VerifyConnection)
	require.True(t, insecure.TLSClientConfig.InsecureSkipVerify, "the caller's config changed")
}

// A custom TLS dialer may carry the only route or address policy, so a
// transport without DialContext cannot be rebuilt and must refuse requests.
func TestClientRefusesTLSDialerWithoutDialContext(t *testing.T) {
	var dialed bool
	tlsOnly := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("policy dialer")
	}}
	_, err := Client(&http.Client{Transport: tlsOnly}).Get("https://tracker.example/")
	require.ErrorIs(t, err, errTLSDialerOnly)
	require.False(t, dialed)
}
