package testutils

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
)

// NewInteractshServer starts a local stand-in for an interactsh server, so
// clients can register and generate URLs without reaching a public server. It
// returns the server URL and the HTTP client to reach it with. The URL has no
// port because generated interactsh URLs embed its host, so the client dials
// the stand-in whatever address it is asked for.
func NewInteractshServer(t testing.TB) (string, *retryablehttp.Client) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/poll":
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	}))
	t.Cleanup(server.Close)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	return "http://oast.test", retryablehttp.NewWithHTTPClient(&http.Client{Transport: transport}, retryablehttp.DefaultOptionsSingle)
}
