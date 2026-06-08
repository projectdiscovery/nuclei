package autologin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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
