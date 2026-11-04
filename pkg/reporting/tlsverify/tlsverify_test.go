package tlsverify

import (
	"crypto/tls"
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
