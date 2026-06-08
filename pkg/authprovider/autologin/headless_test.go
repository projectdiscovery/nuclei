package autologin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/stretchr/testify/require"
)

// requireChrome skips the test unless a system Chrome/Chromium is installed, so
// CI without a managed-browser download does not fail or hang.
func requireChrome(t *testing.T) {
	t.Helper()
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("no system chrome/chromium found; skipping headless auto-login test")
	}
}

// jsLoginApp serves a login form that is constructed entirely by JavaScript:
// the raw HTML has no <form>, so the static HTTP engine cannot detect or submit
// it — only a real browser that executes JS can. This is the canonical case
// that motivates headless login.
type jsLoginApp struct {
	mu       sync.Mutex
	sessions map[string]bool
}

func newJSLoginApp() *jsLoginApp { return &jsLoginApp{sessions: map[string]bool{}} }

func (a *jsLoginApp) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/dashboard", a.handleDashboard)
	return httptest.NewServer(mux)
}

const jsLoginPage = `<html><head><title>Login</title></head><body>
<div id="app"></div>
<script>
  var f = document.createElement('form');
  f.setAttribute('action', '/login');
  f.setAttribute('method', 'post');
  f.innerHTML = '<input type="email" name="email" autocomplete="username">' +
                '<input type="password" name="password">' +
                '<button type="submit">Sign in</button>';
  document.getElementById('app').appendChild(f);
</script></body></html>`

func (a *jsLoginApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, jsLoginPage)
		return
	}
	_ = r.ParseForm()
	if r.PostFormValue("email") != "dave@example.com" || r.PostFormValue("password") != "p@ss" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, jsLoginPage) // re-render: still a (JS) login page
		return
	}
	token := "sess-dave"
	a.mu.Lock()
	a.sessions[token] = true
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/"})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (a *jsLoginApp) handleDashboard(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	ok := a.sessions[c.Value]
	a.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprint(w, "<html><body><h1>welcome dave</h1></body></html>")
}

func TestLoginHeadless_JSRenderedForm(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := app.server()
	defer srv.Close()

	// Sanity: the HTTP engine cannot handle this page because the form only
	// exists after JS runs — the raw HTML has no <form>.
	_, httpErr := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login",
		Username: "dave@example.com",
		Password: "p@ss",
	})
	require.ErrorIs(t, httpErr, ErrNoLoginForm, "HTTP engine should fail on a JS-rendered form")

	// Headless engine renders the JS, fills and submits the form, and captures
	// the session.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "headless login should capture the session cookie")

	// The captured session must authenticate against a protected route.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/dashboard", nil)
	req.Header.Set("Cookie", session.CookieHeader)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLoginHeadless_WrongPasswordFails(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := app.server()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "wrong",
		SettleTime: 1500 * time.Millisecond,
	})
	require.ErrorIs(t, err, ErrLoginFailed)
}
