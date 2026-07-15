package authprovider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

// autoLoginE2EApp is a hermetic, CSRF-protected, cookie-session web app used to
// exercise the whole auto-login autonomy path through the real FileAuthProvider:
// secrets-file parse -> dynamic validate -> auto-login callback -> form detect +
// submit -> captured session applied as a cookie strategy -> reauth-on-401.
//
// Each successful login mints a *fresh* session token (sess-N), so a
// re-authentication is observable as a changed applied cookie value.
type autoLoginE2EApp struct {
	mu         sync.Mutex
	loginCount int
	validToken string // the currently valid session token; "" means expired
}

func (a *autoLoginE2EApp) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/dashboard", a.handleDashboard)
	return httptest.NewServer(mux)
}

func (a *autoLoginE2EApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf-secret", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>
			<form action="/login" method="post">
				<input type="hidden" name="csrf" value="csrf-secret">
				<input type="email" name="email" autocomplete="username">
				<input type="password" name="password">
				<input type="submit" name="commit" value="Sign in">
			</form></body></html>`)
		return
	}

	_ = r.ParseForm()
	csrf, err := r.Cookie("csrftoken")
	if err != nil || r.PostFormValue("csrf") != csrf.Value {
		http.Error(w, "csrf mismatch", http.StatusForbidden)
		return
	}
	if r.PostFormValue("email") != "alice@example.com" || r.PostFormValue("password") != "s3cr3t" {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<form action="/login" method="post"><input type="password" name="password"></form>`)
		return
	}
	a.mu.Lock()
	a.loginCount++
	a.validToken = fmt.Sprintf("sess-%d", a.loginCount)
	token := a.validToken
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/"})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (a *autoLoginE2EApp) handleDashboard(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	a.mu.Lock()
	valid := a.validToken
	a.mu.Unlock()
	if err != nil || valid == "" || c.Value != valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, _ = fmt.Fprint(w, "welcome")
}

func (a *autoLoginE2EApp) expire() {
	a.mu.Lock()
	a.validToken = ""
	a.mu.Unlock()
}

// appliedSessionCookie applies the strategies to a fresh request and returns the
// value of the "session" cookie they set (or "").
func appliedSessionCookie(strategies []authx.AuthStrategy, target string) string {
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	for _, s := range strategies {
		s.Apply(req)
	}
	if c, err := req.Cookie("session"); err == nil {
		return c.Value
	}
	return ""
}

func TestAutoLogin_FullLifecycle_E2E(t *testing.T) {
	app := &autoLoginE2EApp{}
	srv := app.server()
	defer srv.Close()

	host := srv.Listener.Addr().String()
	secrets := fmt.Sprintf(`id: auto-login-e2e
info:
  name: auto-login-e2e
dynamic:
  - domains:
      - "%s"
    auto-login:
      login-url: "%s/login"
      username: "alice@example.com"
      password: "s3cr3t"
    reauth-status-codes:
      - 401
`, host, srv.URL)

	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "auth.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(secrets), 0o644))

	// callback is nil: auto-login dynamics need no template store.
	provider, err := NewFileAuthProvider(secretsPath, nil, nil)
	require.NoError(t, err)

	// Pre-fetch performs the real form login.
	require.NoError(t, provider.PreFetchSecrets())

	strategies := provider.LookupAddr(host)
	require.NotEmpty(t, strategies, "auto-login secret should be scoped to the app host")

	// 1. The captured session authenticates against the protected route.
	cookie1 := appliedSessionCookie(strategies, srv.URL+"/dashboard")
	require.Equal(t, "sess-1", cookie1, "first login should apply session token sess-1")
	requireDashboard(t, srv.URL, cookie1, http.StatusOK)

	// 2. Server-side session expiry: the applied cookie now 401s.
	app.expire()
	requireDashboard(t, srv.URL, cookie1, http.StatusUnauthorized)

	// 3. Surface the 401 to the strategy (as the scan engine does), which marks
	//    the dynamic session stale for re-authentication.
	reauthTriggered := false
	for _, s := range strategies {
		if insp, ok := s.(authx.ResponseInspector); ok {
			if insp.OnResponse(http.StatusUnauthorized) {
				reauthTriggered = true
			}
		}
	}
	require.True(t, reauthTriggered, "401 should trigger re-authentication on the dynamic strategy")

	// 4. The next application re-runs the form login and applies a *fresh*
	//    session token, restoring access.
	cookie2 := appliedSessionCookie(strategies, srv.URL+"/dashboard")
	require.Equal(t, "sess-2", cookie2, "re-auth should apply the freshly minted session token")
	requireDashboard(t, srv.URL, cookie2, http.StatusOK)

	require.Equal(t, 2, app.loginCount, "login form should have been submitted exactly twice")
}

func requireDashboard(t *testing.T, baseURL, sessionCookie string, wantStatus int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/dashboard", nil)
	if sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionCookie})
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, wantStatus, resp.StatusCode)
}
