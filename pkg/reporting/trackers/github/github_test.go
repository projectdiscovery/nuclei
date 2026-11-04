package github

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testEvent() *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "https://target.example",
		Info:       model.Info{Name: "test", SeverityHolder: severity.Holder{Severity: severity.High}},
	}
}

func clientWithTransport(rt http.RoundTripper) *retryablehttp.Client {
	c := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	c.HTTPClient = &http.Client{Transport: rt}
	return c
}

// The tracker must send every request through the caller's client, so a
// caller's address policy also covers the GitHub API base URL.
func TestNewUsesCallerHTTPClient(t *testing.T) {
	var serverHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1,"html_url":"https://github.example/o/r/issues/1"}`))
	}))
	defer srv.Close()

	t.Run("requests go through the caller's transport", func(t *testing.T) {
		var seen atomic.Int32
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen.Add(1)
			require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			return http.DefaultTransport.RoundTrip(r)
		})
		tracker, err := New(&Options{BaseURL: srv.URL + "/", Username: "u", Owner: "o", ProjectName: "r", Token: "test-token", HttpClient: clientWithTransport(rt)})
		require.NoError(t, err)
		_, err = tracker.CreateIssue(testEvent())
		require.NoError(t, err)
		require.Positive(t, seen.Load())
	})

	t.Run("a refusing transport stops the request", func(t *testing.T) {
		before := serverHits.Load()
		denied := errors.New("denied by address policy")
		rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, denied })
		tracker, err := New(&Options{BaseURL: srv.URL + "/", Username: "u", Owner: "o", ProjectName: "r", Token: "test-token", HttpClient: clientWithTransport(rt)})
		require.NoError(t, err)
		_, err = tracker.CreateIssue(testEvent())
		require.ErrorContains(t, err, "denied by address policy")
		require.Equal(t, before, serverHits.Load(), "the request reached the server")
	})
}

func TestNewRefusesUntrustedCertificateFromInsecureCallerClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1}`))
	}))
	defer srv.Close()

	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	tracker, err := New(&Options{BaseURL: srv.URL + "/", Username: "u", Owner: "o", ProjectName: "r", Token: "test-token", HttpClient: clientWithTransport(insecure)})
	require.NoError(t, err)
	_, err = tracker.CreateIssue(testEvent())
	require.ErrorContains(t, err, "certificate")
}

type wrappingTransport struct{ base http.RoundTripper }

func (w *wrappingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return w.base.RoundTrip(r)
}
func (w *wrappingTransport) Unwrap() http.RoundTripper { return w.base }

// The scan client wraps its transport and, with a SOCKS proxy, does TLS in its
// own dialer with the scan TLS config, which skips verification.
func TestNewRefusesUntrustedCertificateFromInsecureTLSDialer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1}`))
	}))
	defer srv.Close()

	var dialed atomic.Int32
	var dialer net.Dialer
	base := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Add(1)
			return dialer.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, &tls.Config{InsecureSkipVerify: true}), nil
		},
	}
	tracker, err := New(&Options{BaseURL: srv.URL + "/", Username: "u", Owner: "o", ProjectName: "r", Token: "test-token", HttpClient: clientWithTransport(&wrappingTransport{base: base})})
	require.NoError(t, err)
	_, err = tracker.CreateIssue(testEvent())
	require.ErrorContains(t, err, "certificate")
	require.Positive(t, dialed.Load(), "the caller's dialer was not used")
}
