package autologin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBlockRedirectReplay(t *testing.T) {
	const a, b = "http://127.0.0.1:8001/do-login", "http://127.0.0.1:8002/steal"
	require.True(t, blockRedirectReplay(http.MethodPost, a, true, b), "cross-origin 307/308 POST must be blocked")
	require.False(t, blockRedirectReplay(http.MethodPost, a, true, "http://127.0.0.1:8001/next"), "same-origin 307/308 POST is allowed")
	require.False(t, blockRedirectReplay(http.MethodGet, a, true, b), "a redirect that became GET carries no body")
	require.False(t, blockRedirectReplay(http.MethodHead, a, true, b))
	require.True(t, blockRedirectReplay(http.MethodPut, a, true, b))
	require.True(t, blockRedirectReplay(http.MethodPost, "", false, b), "unknown redirect source fails closed")
	require.True(t, blockRedirectReplay(http.MethodPost, "http://127.0.0.1:8001/x", true, "https://127.0.0.1:8001/x"), "scheme change is a different origin")
}

// redirectApps starts a login origin whose form submit answers 307 to target
// (resolved lazily), and a second origin that counts POSTs it receives.
func redirectApps(t *testing.T, sameOriginTarget bool) (login *httptest.Server, other *httptest.Server, posts *atomic.Int32) {
	t.Helper()
	posts = &atomic.Int32{}
	other = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "other", Path: "/"})
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	t.Cleanup(other.Close)
	login = httptest.NewServer(nil)
	login.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			_, _ = w.Write([]byte(`<html><body><form method="post" action="/do-login"><input name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></body></html>`))
		case r.URL.Path == "/do-login":
			target := other.URL + "/steal"
			if sameOriginTarget {
				target = login.URL + "/final"
			}
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		case r.URL.Path == "/final":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		default:
			http.NotFound(w, r)
		}
	})
	t.Cleanup(login.Close)
	return login, other, posts
}

func TestLoginHeadless_BlocksCrossOriginRedirectReplay(t *testing.T) {
	requireChrome(t)
	login, _, posts := redirectApps(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := LoginHeadless(ctx, Config{
		LoginURL:   login.URL + "/login",
		Username:   "admin",
		Password:   "secret",
		SettleTime: 1500 * time.Millisecond,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "different origin")
	require.Zero(t, posts.Load(), "the login POST must not reach the other origin")
}

func TestLoginHeadless_AllowsSameOriginRedirectReplay(t *testing.T) {
	requireChrome(t)
	login, _, posts := redirectApps(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   login.URL + "/login",
		Username:   "admin",
		Password:   "secret",
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Cookies)
	require.Zero(t, posts.Load())
}

func TestLoginHeadless_AllowCrossOriginActionPermitsReplay(t *testing.T) {
	requireChrome(t)
	login, _, posts := redirectApps(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, _ = LoginHeadless(ctx, Config{
		LoginURL:               login.URL + "/login",
		Username:               "admin",
		Password:               "secret",
		AllowCrossOriginAction: true,
		SettleTime:             1500 * time.Millisecond,
	})
	require.Equal(t, int32(1), posts.Load(), "with allow-cross-origin-action the browser follows the 307")
}
