package pdcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/gologger"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/stretchr/testify/require"
)

func newTestUploadWriter(t *testing.T, gotKey *atomic.Value) (*UploadWriter, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get(pdcpauth.ApiKeyHeaderName))
		_, _ = w.Write([]byte(`{"id":"abcdefghij0123456789"}`))
	}))
	t.Cleanup(srv.Close)
	creds := &pdcpauth.PDCPCredentials{APIKey: "test-key", Server: srv.URL}
	u, err := NewUploadWriter(context.Background(), gologger.DefaultLogger, creds)
	require.NoError(t, err)
	t.Cleanup(u.Close)
	return u, srv
}

func TestUploadRejectsUntrustedCertificate(t *testing.T) {
	var gotKey atomic.Value
	u, _ := newTestUploadWriter(t, &gotKey)

	err := u.upload([]byte("{}\n"))
	require.Error(t, err)
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknownAuthority)
	require.Nil(t, gotKey.Load(), "API key must not reach a server with an untrusted certificate")
}

func TestUploadTrustedCertificate(t *testing.T) {
	var gotKey atomic.Value
	u, srv := newTestUploadWriter(t, &gotKey)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	transport, ok := u.client.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok)
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	require.NoError(t, u.upload([]byte("{}\n")))
	require.Equal(t, "test-key", gotKey.Load())
	require.Equal(t, "abcdefghij0123456789", u.scanID)
}
