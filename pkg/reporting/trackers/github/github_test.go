package github

import (
	"crypto/tls"
	"errors"
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

// The scan client can skip TLS verification; the tracker must not send the
// token over such a connection, and must not change the caller's client.
func TestVerifyingClientTurnsOnTLSVerification(t *testing.T) {
	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	caller := &http.Client{Transport: insecure}

	got := verifyingClient(caller)
	gotTransport, ok := got.Transport.(*http.Transport)
	require.True(t, ok)
	require.False(t, gotTransport.TLSClientConfig.InsecureSkipVerify)
	require.True(t, insecure.TLSClientConfig.InsecureSkipVerify, "the caller's transport changed")

	secure := &http.Client{Transport: &http.Transport{}}
	require.Same(t, secure, verifyingClient(secure))
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
