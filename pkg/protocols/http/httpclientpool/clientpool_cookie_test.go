package httpclientpool

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestGet_ReissuedCookieReplacesCapturedCookie(t *testing.T) {
	for _, explicitJar := range []bool{false, true} {
		name := "default jar"
		if explicitJar {
			name = "input jar"
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan []*http.Cookie, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Cookies()
				if cookie, err := r.Cookie("session"); err == nil && cookie.Value == "old'" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
				}
			}))
			defer server.Close()

			opts := newTestOptions(t, t.Name())
			cfg := &Configuration{Connection: &ConnectionConfiguration{}}
			if explicitJar {
				jar, err := cookiejar.New(nil)
				require.NoError(t, err)
				cfg.Connection.SetCookieJar(jar)
			}
			client, err := Get(opts, cfg, server.URL)
			require.NoError(t, err)

			for i, value := range []string{"old", "old'", "old"} {
				req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
				require.NoError(t, err)
				req.Header.Set("Cookie", "session="+value+"; preference=dark")
				resp, err := client.Do(req)
				require.NoError(t, err)
				_, readErr := io.Copy(io.Discard, resp.Body)
				closeErr := resp.Body.Close()
				require.NoError(t, readErr)
				require.NoError(t, closeErr)

				wantSession := value
				if i == 2 {
					wantSession = "reissued"
				}
				var pairs []string
				for _, cookie := range <-received {
					pairs = append(pairs, cookie.Name+"="+cookie.Value)
				}
				require.ElementsMatch(t, []string{"session=" + wantSession, "preference=dark"}, pairs)
			}
		})
	}
}

func TestGet_CookieMergeOnRedirect(t *testing.T) {
	tests := []struct {
		name        string
		cookiePath  string
		reissue     bool
		crossHost   bool
		wantCookies []string
	}{
		{name: "cookie becomes applicable on redirect", cookiePath: "/private", wantCookies: []string{"session=captured; preference=dark", "preference=dark; session=stored"}},
		{name: "cookie reissued by redirect", reissue: true, wantCookies: []string{"session=captured; preference=dark", "preference=dark; session=reissued"}},
		{name: "cookie not sent to another host", cookiePath: "/", crossHost: true, wantCookies: []string{"preference=dark; session=stored", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("Cookie")
				if r.URL.Path == "/start" {
					targetURL := "/private/target"
					if test.crossHost {
						targetURL = "http://" + strings.Replace(r.Host, "127.0.0.1", "localhost", 1) + targetURL
					}
					if test.reissue {
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
					}
					http.Redirect(w, r, targetURL, http.StatusFound)
				}
			}))
			defer server.Close()
			opts := newTestOptions(t, t.Name())
			parsed, err := url.Parse(server.URL)
			require.NoError(t, err)
			client, err := Get(opts, &Configuration{RedirectFlow: FollowAllRedirect, MaxRedirects: 5}, parsed.Host)
			require.NoError(t, err)
			// Connect both host names to the test listener without DNS.
			transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			client.HTTPClient.Transport = transport
			if test.cookiePath != "" {
				client.HTTPClient.Jar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "stored", Path: test.cookiePath}})
			}
			req, err := retryablehttp.NewRequest(http.MethodGet, server.URL+"/start", nil)
			require.NoError(t, err)
			req.Header.Set("Cookie", "session=captured; preference=dark")
			resp, err := client.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Len(t, received, 2)
			for _, want := range test.wantCookies {
				require.Equal(t, want, <-received)
			}
		})
	}
}

func TestGet_CookieMergeOnRetry(t *testing.T) {
	received := make(chan string, 2)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Cookie")
		if attempts.Add(1) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	opts := newTestOptions(t, t.Name())
	opts.Retries = 1
	client, err := Get(opts, &Configuration{}, server.URL)
	require.NoError(t, err)
	client.CheckRetry = func(_ context.Context, resp *http.Response, err error) (bool, error) {
		return resp != nil && resp.StatusCode == http.StatusServiceUnavailable, err
	}
	client.Backoff = func(_, _ time.Duration, _ int, _ *http.Response) time.Duration { return 0 }
	req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session=captured; preference=dark")
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Len(t, received, 2)
	require.Equal(t, "session=captured; preference=dark", <-received)
	require.Equal(t, "preference=dark; session=reissued", <-received)
	require.Equal(t, "preference=dark; session=reissued", req.Header.Get("Cookie"))
}

func TestGet_CookieHeaderMerge(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		cookies []*http.Cookie
		path    string
		host    string
		want    string
	}{
		{name: "jar replaces captured duplicates", headers: []string{"session=old; session=older; preference=dark"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "preference=dark; session=new"},
		{name: "unrelated malformed payload is preserved", headers: []string{`session=old; payload=bad"quote; Session=case-sensitive`}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: `payload=bad"quote; Session=case-sensitive; session=new`},
		{name: "embedded delimiters and whitespace are preserved", headers: []string{"session=old; payload=\"a;b\"; padding=bad \t; ; other=kept"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "payload=\"a;b\"; padding=bad \t; ; other=kept; session=new"},
		{name: "cookie name inside quoted payload is preserved", headers: []string{`session=old; payload="a;session=probe"`}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: `payload="a;session=probe"; session=new`},
		{name: "conflict after quoted payload is removed", headers: []string{`payload="a;session=probe"; session=old`}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: `payload="a;session=probe"; session=new`},
		{name: "escaped quote inside payload is preserved", headers: []string{`session=old; payload="a\";session=probe"`}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: `payload="a\";session=probe"; session=new`},
		{name: "unmatched quote inside payload is preserved", headers: []string{`session=old; payload="a;session=probe`}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: `payload="a;session=probe; session=new`},
		{name: "trailing payload whitespace is preserved", headers: []string{"session=old; payload=bad \t"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "payload=bad \t; session=new"},
		{name: "multiple cookie headers", headers: []string{"session=old", "preference=dark"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "preference=dark; session=new"},
		{name: "multiple unrelated cookie headers", headers: []string{"preference=dark", "other=kept"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "preference=dark; other=kept; session=new"},
		{name: "jar only", cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "session=new"},
		{name: "empty jar", headers: []string{`session=old; payload=bad"quote`}, want: `session=old; payload=bad"quote`},
		{name: "secure cookie excluded on http", host: "example.test", headers: []string{"session=old"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/", Secure: true}}, want: "session=old"},
		{name: "cookie outside path", headers: []string{"session=old"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/private"}}, want: "session=old"},
		{name: "same name at different jar paths", path: "/private/test", headers: []string{"session=old"}, cookies: []*http.Cookie{{Name: "session", Value: "root", Path: "/"}, {Name: "session", Value: "private", Path: "/private"}}, want: "session=private; session=root"},
		{name: "host override", host: "example.test", headers: []string{"session=old"}, cookies: []*http.Cookie{{Name: "session", Value: "new", Path: "/"}}, want: "session=new"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- strings.Join(r.Header.Values("Cookie"), "; ")
			}))
			defer server.Close()
			opts := newTestOptions(t, t.Name())
			parsed, err := url.Parse(server.URL)
			require.NoError(t, err)
			client, err := Get(opts, &Configuration{}, parsed.Host)
			require.NoError(t, err)
			cookieURL := *parsed
			if test.host != "" {
				cookieURL.Host = test.host
			}
			client.HTTPClient.Jar.SetCookies(&cookieURL, test.cookies)
			req, err := retryablehttp.NewRequest(http.MethodGet, server.URL+test.path, nil)
			require.NoError(t, err)
			req.Host = test.host
			req.Header["Cookie"] = test.headers
			resp, err := client.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, test.want, <-received)
		})
	}
}

func BenchmarkGet_CookieReuse(b *testing.B) {
	for _, header := range []string{"", "session=captured; preference=dark"} {
		name := "no captured cookies"
		if header != "" {
			name = "captured cookies"
		}
		b.Run(name, func(b *testing.B) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			defer server.Close()
			opts := setupPRBenchOptions(b, b.Name())
			parsed, err := url.Parse(server.URL)
			require.NoError(b, err)
			client, err := Get(opts, &Configuration{}, parsed.Host)
			require.NoError(b, err)
			client.HTTPClient.Jar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "reissued", Path: "/"}})
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
				require.NoError(b, err)
				if header != "" {
					req.Header.Set("Cookie", header)
				}
				resp, err := client.Do(req)
				require.NoError(b, err)
				require.NoError(b, resp.Body.Close())
			}
		})
	}
}
