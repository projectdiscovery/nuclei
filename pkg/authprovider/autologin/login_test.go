package autologin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// loginApp is a hermetic web app with a realistic, CSRF-protected, cookie-based
// login flow used to exercise the auto-login engine end to end:
//   - GET /login sets a per-visitor csrf cookie and renders a form echoing it in
//     a hidden input.
//   - POST /login validates the csrf (hidden field must equal the cookie),
//     checks the credentials, and on success sets a `session` cookie and 302s to
//     /dashboard.
//   - GET /dashboard returns 200 only when a valid session cookie is presented.
type loginApp struct {
	mu       sync.Mutex
	sessions map[string]bool // valid session tokens
	user     string
	pass     string
}

func newLoginApp(user, pass string) *loginApp {
	return &loginApp{sessions: map[string]bool{}, user: user, pass: pass}
}

func (a *loginApp) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/dashboard", a.handleDashboard)
	return httptest.NewServer(mux)
}

func (a *loginApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Seed a CSRF cookie and echo it into the form.
		csrf := "csrf-" + fmt.Sprint(len(a.sessions)) + "-tok"
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: csrf, Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
			<form action="/login" method="post">
				<input type="hidden" name="csrf" value="%s">
				<input type="text" name="email" autocomplete="username">
				<input type="password" name="password">
				<input type="submit" name="commit" value="Sign in">
			</form>
		</body></html>`, csrf)
		return
	}

	// POST: validate CSRF against the cookie, then credentials.
	_ = r.ParseForm()
	csrfCookie, err := r.Cookie("csrftoken")
	if err != nil || r.PostFormValue("csrf") != csrfCookie.Value {
		http.Error(w, "csrf mismatch", http.StatusForbidden)
		return
	}
	if r.PostFormValue("email") != a.user || r.PostFormValue("password") != a.pass {
		// Re-render the login form on failure (no session set).
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><p>Invalid credentials</p>
			<form action="/login" method="post">
				<input type="text" name="email">
				<input type="password" name="password">
			</form></body></html>`)
		return
	}
	token := "sess-" + r.PostFormValue("email")
	a.mu.Lock()
	a.sessions[token] = true
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/"})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (a *loginApp) handleDashboard(w http.ResponseWriter, r *http.Request) {
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
	fmt.Fprint(w, "welcome to your dashboard")
}

func TestLogin_CSRFFormAndSessionCookie(t *testing.T) {
	app := newLoginApp("alice@example.com", "s3cr3t")
	srv := app.server()
	defer srv.Close()

	session, err := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login",
		Username: "alice@example.com",
		Password: "s3cr3t",
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Cookies, "should capture session cookie")

	// The captured session must actually authenticate against a protected route.
	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "session cookie must be captured")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/dashboard", nil)
	req.Header.Set("Cookie", session.CookieHeader)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "captured session should grant access to /dashboard")
}

func TestLogin_WrongPasswordFails(t *testing.T) {
	app := newLoginApp("alice@example.com", "s3cr3t")
	srv := app.server()
	defer srv.Close()

	_, err := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login",
		Username: "alice@example.com",
		Password: "wrong-password",
	})
	require.ErrorIs(t, err, ErrLoginFailed)
}

func TestLogin_FieldOverride(t *testing.T) {
	// Force the username field name via override; detection would pick "email"
	// anyway, but this verifies the override path submits correctly.
	app := newLoginApp("bob@example.com", "hunter2")
	srv := app.server()
	defer srv.Close()

	session, err := Login(context.Background(), nil, Config{
		LoginURL:      srv.URL + "/login",
		Username:      "bob@example.com",
		Password:      "hunter2",
		UsernameField: "email",
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Cookies)
}

// tokenApp returns a JSON token in the login response body instead of setting a
// cookie, to exercise TokenRegex-based capture.
func tokenApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<form action="/api/login" method="post">
				<input type="text" name="user">
				<input type="password" name="password">
			</form>`)
			return
		}
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("user") == "carol" && r.PostFormValue("password") == "pw" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"eyJhbGciOiJI.payload.sig","expires_in":3600}`)
			return
		}
		http.Error(w, "bad creds", http.StatusUnauthorized)
	})
	return httptest.NewServer(mux)
}

func TestLogin_TokenExtraction(t *testing.T) {
	srv := tokenApp()
	defer srv.Close()

	session, err := Login(context.Background(), nil, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "carol",
		Password:   "pw",
		TokenRegex: `"access_token":"([^"]+)"`,
	})
	require.NoError(t, err)
	require.Equal(t, "eyJhbGciOiJI.payload.sig", session.Token)
}

// getFormApp serves a GET-method login form (credentials travel in the query
// string). It exercises the GET submission branch of Login.
func getFormApp(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// A submit is any GET carrying the password param.
		if q.Get("password") != "" {
			if q.Get("user") == user && q.Get("password") == pass && q.Get("realm") == "corp" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body>welcome, no form here</body></html>`)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><form method="get" action="/login">
				<input type="text" name="user"><input type="password" name="password"></form></body></html>`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form method="get" action="/login">
			<input type="hidden" name="realm" value="corp">
			<input type="text" name="user" autocomplete="username">
			<input type="password" name="password">
		</form></body></html>`)
	})
	return httptest.NewServer(mux)
}

func TestLogin_GetMethodForm(t *testing.T) {
	srv := getFormApp("dave", "pw123")
	defer srv.Close()

	session, err := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login",
		Username: "dave",
		Password: "pw123",
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Cookies, "GET-form login should still capture the session cookie")
	// The hidden 'realm' default must have been carried into the query string.
	require.Contains(t, session.FinalURL, "realm=corp")
}

// extraFieldApp requires an additional non-form field (e.g. a tenant id) that is
// not present in the markup, so it must be supplied via Config.ExtraFields.
func extraFieldApp(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<form action="/login" method="post">
				<input type="text" name="user"><input type="password" name="password"></form>`)
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("user") == user && r.PostFormValue("password") == pass && r.PostFormValue("tenant") == "acme" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			fmt.Fprint(w, "<html><body>signed in</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/login" method="post"><input type="password" name="password"></form>`)
	})
	return httptest.NewServer(mux)
}

func TestLogin_ExtraFields(t *testing.T) {
	srv := extraFieldApp("erin", "pw")
	defer srv.Close()

	// Without the extra field the login must fail (re-prompted).
	_, err := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login", Username: "erin", Password: "pw",
	})
	require.ErrorIs(t, err, ErrLoginFailed)

	// Supplying the tenant via ExtraFields must succeed.
	session, err := Login(context.Background(), nil, Config{
		LoginURL:    srv.URL + "/login",
		Username:    "erin",
		Password:    "pw",
		ExtraFields: map[string]string{"tenant": "acme"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Cookies)
}

func TestProxyTransport(t *testing.T) {
	tr, err := proxyTransport("http://127.0.0.1:8080")
	require.NoError(t, err)
	require.NotNil(t, tr.Proxy, "http proxy must set Transport.Proxy")

	tr, err = proxyTransport("socks5://127.0.0.1:1080")
	require.NoError(t, err)
	require.NotNil(t, tr.DialContext, "socks5 proxy must set Transport.DialContext")

	_, err = proxyTransport("ftp://127.0.0.1:21")
	require.Error(t, err, "unsupported proxy scheme must error")
}

// TestLogin_HTTPProxy proves the HTTP engine actually routes through cfg.Proxy:
// the login target host is unresolvable, so the flow can only succeed if every
// request is sent to the proxy (which serves the login app by path).
func TestLogin_HTTPProxy(t *testing.T) {
	var proxyHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<form action="/login" method="post">
				<input type="text" name="user"><input type="password" name="password"></form>`)
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("user") == "frank" && r.PostFormValue("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			fmt.Fprint(w, "<html><body>signed in</body></html>")
			return
		}
		fmt.Fprint(w, `<form action="/login" method="post"><input type="password" name="password"></form>`)
	})
	proxySrv := httptest.NewServer(mux)
	defer proxySrv.Close()

	session, err := Login(context.Background(), nil, Config{
		// Unresolvable host: only reachable if the proxy is honored.
		LoginURL: "http://login.invalid.test/login",
		Username: "frank",
		Password: "pw",
		Proxy:    proxySrv.URL,
	})
	require.NoError(t, err, "login should succeed via the proxy")
	require.NotEmpty(t, session.Cookies)
	require.GreaterOrEqual(t, atomic.LoadInt32(&proxyHits), int32(2), "both GET and POST must traverse the proxy")
}

func TestLogin_NoFormIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>no form here</body></html>")
	}))
	defer srv.Close()

	_, err := Login(context.Background(), nil, Config{
		LoginURL: srv.URL + "/login",
		Username: "x",
		Password: "y",
	})
	require.ErrorIs(t, err, ErrNoLoginForm)
}
