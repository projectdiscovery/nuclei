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

// twoStepLoginPage is a username-first flow: the password field is hidden until
// the "Next" button is clicked, mimicking Google/Microsoft-style logins.
const twoStepLoginPage = `<html><head><title>Login</title></head><body>
<form id="f" action="/login" method="post">
  <input type="email" name="email" id="email">
  <button type="button" id="next">Next</button>
  <div id="pwwrap" style="display:none">
    <input type="password" name="password" id="password">
    <button type="submit" id="submit">Sign in</button>
  </div>
</form>
<script>
  document.getElementById('next').addEventListener('click', function () {
    document.getElementById('pwwrap').style.display = 'block';
  });
</script></body></html>`

func TestLoginHeadless_MultiStep(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, twoStepLoginPage)
				return
			}
			_ = r.ParseForm()
			if r.PostFormValue("email") != "dave@example.com" || r.PostFormValue("password") != "p@ss" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, twoStepLoginPage)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-dave", Path: "/"})
			app.mu.Lock()
			app.sessions["sess-dave"] = true
			app.mu.Unlock()
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
		mux.HandleFunc("/dashboard", app.handleDashboard)
		return mux
	}())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1 * time.Second,
		Steps: []LoginStep{
			{Action: "fill", Selector: "#email", Value: "{{username}}"},
			{Action: "click", Selector: "#next"},
			{Action: "waitvisible", Selector: "#password"},
			{Action: "fill", Selector: "#password", Value: "{{password}}"},
			{Action: "click", Selector: "#submit"},
		},
	})
	require.NoError(t, err)

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "multi-step login should capture the session cookie")
}

// spaTokenPage is a pure-SPA login: on submit JS validates the credentials
// client-side, stores a JWT in localStorage (no cookie at all) and swaps in a
// logged-in view. This is the canonical "token lives in web storage" case that
// motivates storage capture/replay.
const spaTokenPage = `<html><head><title>SPA</title></head><body>
<form id="f">
  <input type="email" name="email" id="email">
  <input type="password" name="password" id="password">
  <button type="submit" id="submit">Sign in</button>
</form>
<script>
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var email = document.getElementById('email').value;
    var pw = document.getElementById('password').value;
    if (email === 'dave@example.com' && pw === 'p@ss') {
      window.localStorage.setItem('auth_token', 'eyJhbGciOiJI.payload.sig');
      window.sessionStorage.setItem('csrf', 'abc123');
      document.body.innerHTML = '<h1>welcome dave</h1>';
    } else {
      document.body.innerHTML += '<p>bad creds</p>';
    }
  });
</script></body></html>`

func TestLoginHeadless_LocalStorageToken(t *testing.T) {
	requireChrome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, spaTokenPage)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		TokenRegex: `(eyJ[A-Za-z0-9._-]+)`,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Empty(t, session.Cookies, "SPA login sets no cookie")
	require.Equal(t, "eyJhbGciOiJI.payload.sig", session.Token, "token must be extracted from localStorage")
	require.Equal(t, "eyJhbGciOiJI.payload.sig", session.LocalStorage["auth_token"], "localStorage must be captured")
	require.Equal(t, "abc123", session.SessionStorage["csrf"], "sessionStorage must be captured")
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

// disabledSubmitPage mimics a framework-validated form (e.g. Angular/Juice
// Shop): the submit button starts disabled and is only enabled once both fields
// have received input events. A naive click-immediately submitter hangs on the
// disabled button; the engine must settle (so the field input enables the
// button) and wait for the button to become interactable before clicking.
const disabledSubmitPage = `<html><head><title>Login</title></head><body>
<form id="f" action="/login" method="post">
  <input type="email" name="email" id="email">
  <input type="password" name="password" id="password">
  <button type="submit" id="submit" disabled>Sign in</button>
</form>
<script>
  var email = document.getElementById('email');
  var pw = document.getElementById('password');
  var btn = document.getElementById('submit');
  function check() { btn.disabled = !(email.value && pw.value); }
  email.addEventListener('input', check);
  pw.addEventListener('input', check);
</script></body></html>`

func TestLoginHeadless_SubmitDisabledUntilValid(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, disabledSubmitPage)
				return
			}
			_ = r.ParseForm()
			if r.PostFormValue("email") != "dave@example.com" || r.PostFormValue("password") != "p@ss" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, disabledSubmitPage)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-dave", Path: "/"})
			app.mu.Lock()
			app.sessions["sess-dave"] = true
			app.mu.Unlock()
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
		mux.HandleFunc("/dashboard", app.handleDashboard)
		return mux
	}())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err, "engine must wait for the submit button to become interactable")

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "login should succeed once the button is enabled")
}

// enterSubmitPage has no clickable submit control and submits only when Enter is
// pressed in the password field (common in minimal SPA forms). It exercises the
// engine's Enter-to-submit fallback when no submit button is found.
const enterSubmitPage = `<html><head><title>Login</title></head><body>
<form id="f" action="/login" method="post">
  <input type="email" name="email" id="email">
  <input type="password" name="password" id="password">
</form>
<script>
  document.getElementById('password').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { document.getElementById('f').submit(); }
  });
</script></body></html>`

func TestLoginHeadless_EnterSubmitFallback(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, enterSubmitPage)
				return
			}
			_ = r.ParseForm()
			if r.PostFormValue("email") != "dave@example.com" || r.PostFormValue("password") != "p@ss" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, enterSubmitPage)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-dave", Path: "/"})
			app.mu.Lock()
			app.sessions["sess-dave"] = true
			app.mu.Unlock()
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
		mux.HandleFunc("/dashboard", app.handleDashboard)
		return mux
	}())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err, "engine must fall back to Enter-to-submit when no submit button exists")

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "Enter-to-submit fallback should log in")
}

func TestDetectStorageJWT(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYXZlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	t.Run("preferred key wins over other JWT-shaped values", func(t *testing.T) {
		other := "eyJraWQiOiJvdGhlciJ9.eyJub3RpdCI6dHJ1ZX0.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		got := detectStorageJWT(map[string]string{"random_blob": other, "token": jwt})
		require.Equal(t, jwt, got, "the value under a preferred key should be chosen")
	})

	t.Run("extracts JWT embedded in JSON", func(t *testing.T) {
		got := detectStorageJWT(map[string]string{"auth": `{"access_token":"` + jwt + `","exp":123}`})
		require.Equal(t, jwt, got)
	})

	t.Run("extracts JWT wrapped in quotes", func(t *testing.T) {
		got := detectStorageJWT(map[string]string{"id_token": `"` + jwt + `"`})
		require.Equal(t, jwt, got)
	})

	t.Run("falls back to sessionStorage when localStorage has none", func(t *testing.T) {
		got := detectStorageJWT(map[string]string{"theme": "dark"}, map[string]string{"jwt": jwt})
		require.Equal(t, jwt, got)
	})

	t.Run("returns empty when no JWT present", func(t *testing.T) {
		require.Empty(t, detectStorageJWT(map[string]string{"theme": "dark", "lang": "en"}))
		require.Empty(t, detectStorageJWT(nil, nil))
	})

	t.Run("ignores non-JWT values that merely start with eyJ", func(t *testing.T) {
		require.Empty(t, detectStorageJWT(map[string]string{"x": "eyJustabase64ishstring"}))
	})
}

// spaAutoTokenPage stores a realistic JWT in localStorage under a conventional
// key and sets no cookie, mirroring a token-in-web-storage SPA. It is used to
// verify that the engine surfaces the token even without an explicit TokenRegex.
const spaAutoTokenPage = `<html><head><title>SPA</title></head><body>
<form id="f">
  <input type="email" name="email" id="email">
  <input type="password" name="password" id="password">
  <button type="submit" id="submit">Sign in</button>
</form>
<script>
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var email = document.getElementById('email').value;
    var pw = document.getElementById('password').value;
    if (email === 'dave@example.com' && pw === 'p@ss') {
      window.localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYXZlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
      document.body.innerHTML = '<h1>welcome dave</h1>';
    } else {
      document.body.innerHTML += '<p>bad creds</p>';
    }
  });
</script></body></html>`

func TestLoginHeadless_AutoDetectStorageJWTWithoutRegex(t *testing.T) {
	requireChrome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, spaAutoTokenPage)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   srv.URL + "/login",
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Empty(t, session.Cookies, "SPA login sets no cookie")
	require.Equal(t,
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYXZlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		session.Token,
		"JWT in localStorage must be auto-detected as the session token without a TokenRegex")
}
