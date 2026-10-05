package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func cookieFuzzingClient(t *testing.T, serverURL string, disabled bool) (*Request, *retryablehttp.Client, *httpclientpool.Configuration) {
	t.Helper()
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.Retries = 1
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executorOptions := testutils.NewMockExecuterOptions(options, nil)
	t.Cleanup(executorOptions.RateLimiter.Stop)
	config := &httpclientpool.Configuration{DisableCookie: disabled, RedirectFlow: httpclientpool.FollowAllRedirect, MaxRedirects: 5}
	client, err := httpclientpool.Get(options, config, serverURL)
	require.NoError(t, err)
	return &Request{options: executorOptions}, client, config
}

func cookieMutation(t *testing.T, target, key, value string) (*component.Cookie, *retryablehttp.Request) {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session=old; account=base; preference=dark")
	cookies := component.NewCookie()
	parsed, err := cookies.Parse(req)
	require.NoError(t, err)
	require.True(t, parsed)
	require.NoError(t, cookies.SetValue(key, value))
	rebuilt, err := cookies.Rebuild()
	require.NoError(t, err)
	return cookies, rebuilt
}

func sendCookieMutation(client *retryablehttp.Client, req *retryablehttp.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func TestCookieFuzzingClientIsolation(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "reuse enabled"
		if disabled {
			name = "reuse disabled"
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan string, 2)
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("Cookie")
				<-release
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
			}))
			defer server.Close()
			defer close(release)
			request, cached, config := cookieFuzzingClient(t, server.URL, disabled)
			baseJar := cached.HTTPClient.Jar
			parsed, err := url.Parse(server.URL)
			require.NoError(t, err)
			if baseJar != nil {
				baseJar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}, {Name: "account", Value: "stored", Path: "/"}})
			}
			_, first := cookieMutation(t, server.URL, "session", `old"`)
			_, second := cookieMutation(t, server.URL, "account", "base'")
			clients := make([]*retryablehttp.Client, 2)
			for i, mutation := range []*retryablehttp.Request{first, second} {
				keys := []string{"session"}
				if i == 1 {
					keys = []string{"account"}
				}
				clients[i], err = request.preserveFuzzedCookies(cached, config, server.URL, mutation.Request, keys)
				require.NoError(t, err)
				require.NotSame(t, cached, clients[i])
			}
			errors := make(chan error, 2)
			go func() { errors <- sendCookieMutation(clients[0], first) }()
			go func() { errors <- sendCookieMutation(clients[1], second) }()
			var headers []string
			for i := 0; i < 2; i++ {
				select {
				case header := <-received:
					headers = append(headers, header)
				case <-time.After(5 * time.Second):
					t.Fatal("cookie requests did not overlap")
				}
			}
			// Release both handlers while retaining the deferred close on failures.
			release <- struct{}{}
			release <- struct{}{}
			for i := 0; i < 2; i++ {
				require.NoError(t, <-errors)
			}
			want := []string{`session=old"; preference=dark; account=stored`, "account=base'; preference=dark; session=stored"}
			if disabled {
				want = []string{`session=old"; account=base; preference=dark`, "session=old; account=base'; preference=dark"}
			}
			require.ElementsMatch(t, want, headers)
			again, err := httpclientpool.Get(request.options.Options, config, server.URL)
			require.NoError(t, err)
			require.Same(t, cached, again)
			require.Equal(t, baseJar, cached.HTTPClient.Jar)
			if baseJar != nil {
				require.Contains(t, baseJar.Cookies(parsed), &http.Cookie{Name: "session", Value: "reissued"})
			}
		})
	}
}

func TestCookieFuzzingRetryAndFollowUp(t *testing.T) {
	received := make(chan string, 3)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Cookie")
		if attempts.Add(1) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "account", Value: "fresh", Path: "/"})
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	request, cached, config := cookieFuzzingClient(t, server.URL, false)
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	cached.HTTPClient.Jar.SetCookies(parsed, []*http.Cookie{{Name: "account", Value: "stored", Path: "/"}})
	cookies, mutation := cookieMutation(t, server.URL, "session", `old"`)
	client, err := request.preserveFuzzedCookies(cached, config, server.URL, mutation.Request, []string{"session"})
	require.NoError(t, err)
	// The normal policy does not retry 503 responses. Force this retry to test
	// payload preservation and cookie learning between attempts.
	client.CheckRetry = func(_ context.Context, resp *http.Response, err error) (bool, error) {
		return resp != nil && resp.StatusCode == http.StatusServiceUnavailable, err
	}
	client.Backoff = func(_, _ time.Duration, _ int, _ *http.Response) time.Duration { return 0 }
	require.NoError(t, sendCookieMutation(client, mutation))
	require.NoError(t, cookies.SetValue("session", `old"followup`))
	followup, err := cookies.Rebuild()
	require.NoError(t, err)
	// The time analyzer copies post-parse headers onto rebuilt requests.
	followup.Header = mutation.Header.Clone()
	require.NoError(t, sendCookieMutation(client, followup))
	require.Len(t, received, 3)
	require.Equal(t, `session=old"; preference=dark; account=stored`, <-received)
	require.Equal(t, `session=old"; preference=dark; account=fresh`, <-received)
	require.Equal(t, `session=old"followup; preference=dark; account=fresh`, <-received)
}

func TestCookieFuzzingCrossHostRedirect(t *testing.T) {
	received := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Cookie")
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://"+strings.Replace(r.Host, "127.0.0.1", "localhost", 1)+"/target", http.StatusFound)
		}
	}))
	defer server.Close()
	request, cached, config := cookieFuzzingClient(t, server.URL, false)
	otherURL, err := url.Parse(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	require.NoError(t, err)
	cached.HTTPClient.Jar.SetCookies(otherURL, []*http.Cookie{{Name: "session", Value: "other-host", Path: "/"}})
	_, mutation := cookieMutation(t, server.URL+"/start", "session", `old"`)
	client, err := request.preserveFuzzedCookies(cached, config, server.URL, mutation.Request, []string{"session"})
	require.NoError(t, err)
	require.NoError(t, sendCookieMutation(client, mutation))
	require.Len(t, received, 2)
	require.Equal(t, `session=old"; account=base; preference=dark`, <-received)
	require.Equal(t, "session=other-host", <-received)
}

func TestCookieFuzzingRedirectReturnsToOriginalHost(t *testing.T) {
	received := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Cookie")
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "http://"+strings.Replace(r.Host, "127.0.0.1", "localhost", 1)+"/away", http.StatusFound)
		case "/away":
			http.Redirect(w, r, "http://"+strings.Replace(r.Host, "localhost", "127.0.0.1", 1)+"/target", http.StatusFound)
		}
	}))
	defer server.Close()
	request, cached, config := cookieFuzzingClient(t, server.URL, false)
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	cached.HTTPClient.Jar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}})
	cookies, mutation := cookieMutation(t, server.URL+"/start", "session", `old"`)
	client, err := request.preserveFuzzedCookies(cached, config, server.URL, mutation.Request, []string{"session"})
	require.NoError(t, err)
	require.NoError(t, sendCookieMutation(client, mutation))
	require.Len(t, received, 3)
	require.Equal(t, `session=old"; account=base; preference=dark`, <-received)
	require.Empty(t, <-received)
	require.Equal(t, "session=stored", <-received)
	// The same execution client is used by synchronous analyzer follow-ups.
	// Its next send must restore payload protection after the untrusted chain.
	require.NoError(t, cookies.SetValue("session", `old"followup`))
	followup, err := cookies.Rebuild()
	require.NoError(t, err)
	followup.URL.Path = "/followup"
	require.NoError(t, sendCookieMutation(client, followup))
	require.Equal(t, `session=old"followup; account=base; preference=dark`, <-received)
}

func TestCookieFuzzingTrustedSubdomainRedirect(t *testing.T) {
	received := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Cookie")
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://sub.example.test/target", http.StatusFound)
		}
	}))
	defer server.Close()
	request, cached, config := cookieFuzzingClient(t, "http://example.test", false)
	parsed, err := url.Parse("http://example.test")
	require.NoError(t, err)
	cached.HTTPClient.Jar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "stored", Domain: "example.test", Path: "/"}})
	_, mutation := cookieMutation(t, "http://example.test/start", "session", `old"`)
	client, err := request.preserveFuzzedCookies(cached, config, parsed.Host, mutation.Request, []string{"session"})
	require.NoError(t, err)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client.HTTPClient.Transport = transport
	require.NoError(t, sendCookieMutation(client, mutation))
	require.Len(t, received, 2)
	require.Equal(t, `session=old"; account=base; preference=dark`, <-received)
	require.Equal(t, `session=old"; account=base; preference=dark`, <-received)
}
