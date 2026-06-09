package fuzzplayground

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
)

// This file turns the playground into a small but realistic "modern app" auth
// test bench. It serves a range of login styles seen in the wild — classic
// server-rendered forms, JS/SPA-rendered forms, username-first multi-step flows,
// SPA logins that stash a JWT in web storage, CSRF-protected forms, a
// disabled-until-valid submit button (a real regression class), and an
// OAuth-style redirect dance — plus protected endpoints (whoami) and an
// authenticated, fuzzable endpoint. It lets us exercise the auto-login /
// recording / capture engine and authenticated scanning entirely in-repo,
// without external apps.
//
// Credentials are fixed and shared across every style.
const (
	AuthUsername      = "tester@nuclei.test"
	AuthPassword      = "nuclei-rocks"
	authSessionCookie = "PSESSION"
)

// authStore is a tiny in-memory session/CSRF store for the auth playground.
type authStore struct {
	mu       sync.Mutex
	sessions map[string]string // session token -> username
	csrf     map[string]struct{}
}

func newAuthStore() *authStore {
	// Pre-seed the SPA-token style's fixed session so the JWT it stashes in web
	// storage also authenticates protected APIs (bearer path).
	return &authStore{
		sessions: map[string]string{"spa-static-session": AuthUsername},
		csrf:     map[string]struct{}{},
	}
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// jwtFor returns a JWT-shaped token (eyJ...) so token-regex extraction has a
// realistic target. It is not a real signed JWT; the playground treats the
// session token embedded in it as the source of truth.
func jwtFor(session string) string {
	// header.payload.signature where payload carries the opaque session id
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		hex.EncodeToString([]byte(session)) + ".c2lnbmF0dXJl"
}

func (s *authStore) issue(username string) (session, jwt string) {
	session = randToken()
	s.mu.Lock()
	s.sessions[session] = username
	s.mu.Unlock()
	return session, jwtFor(session)
}

func (s *authStore) userFor(session string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.sessions[session]
	return u, ok
}

func (s *authStore) issueCSRF() string {
	tok := randToken()
	s.mu.Lock()
	s.csrf[tok] = struct{}{}
	s.mu.Unlock()
	return tok
}

func (s *authStore) consumeCSRF(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.csrf[tok]; ok {
		delete(s.csrf, tok)
		return true
	}
	return false
}

// authenticatedUser resolves the caller's identity from either the session
// cookie or a bearer token (the JWT carries the hex-encoded session id).
func (s *authStore) authenticatedUser(ctx echo.Context) (string, bool) {
	if c, err := ctx.Cookie(authSessionCookie); err == nil && c.Value != "" {
		if u, ok := s.userFor(c.Value); ok {
			return u, true
		}
	}
	auth := ctx.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		if sess := sessionFromJWT(strings.TrimPrefix(auth, "Bearer ")); sess != "" {
			if u, ok := s.userFor(sess); ok {
				return u, true
			}
		}
	}
	return "", false
}

// sessionFromJWT extracts the opaque session id embedded in a playground JWT.
func sessionFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	return string(raw)
}

func setSessionCookie(ctx echo.Context, session string) {
	ctx.SetCookie(&http.Cookie{
		Name:     authSessionCookie,
		Value:    session,
		Path:     "/",
		HttpOnly: true,
	})
}

// registerAuthRoutes wires every login style and the protected endpoints onto a
// per-server auth store.
func registerAuthRoutes(e *echo.Echo) {
	st := newAuthStore()

	// 1. Classic server-rendered form login (works with the static HTTP engine).
	e.GET("/auth/form-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, formLoginPage("", ""))
	})
	e.POST("/auth/form-login", func(c echo.Context) error {
		if c.FormValue("username") == AuthUsername && c.FormValue("password") == AuthPassword {
			session, _ := st.issue(AuthUsername)
			setSessionCookie(c, session)
			return c.Redirect(http.StatusFound, "/auth/dashboard")
		}
		return c.HTML(http.StatusOK, formLoginPage(c.FormValue("username"), "Invalid credentials"))
	})

	// 2. CSRF-protected server-rendered form: a hidden token must be echoed back.
	e.GET("/auth/csrf-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, csrfLoginPage(st.issueCSRF(), ""))
	})
	e.POST("/auth/csrf-login", func(c echo.Context) error {
		if !st.consumeCSRF(c.FormValue("csrf_token")) {
			return c.HTML(http.StatusForbidden, csrfLoginPage(st.issueCSRF(), "Invalid CSRF token"))
		}
		if c.FormValue("username") == AuthUsername && c.FormValue("password") == AuthPassword {
			session, _ := st.issue(AuthUsername)
			setSessionCookie(c, session)
			return c.Redirect(http.StatusFound, "/auth/dashboard")
		}
		return c.HTML(http.StatusOK, csrfLoginPage(st.issueCSRF(), "Invalid credentials"))
	})

	// 3. JS/SPA-rendered form: the raw HTML has no <form>; JS builds it and posts
	//    via fetch. Only a real browser can log in here.
	e.GET("/auth/spa-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, spaLoginPage)
	})
	e.POST("/auth/api/login", func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.Bind(&body); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad request"})
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			session, jwt := st.issue(AuthUsername)
			setSessionCookie(c, session)
			return c.JSON(http.StatusOK, map[string]string{"token": jwt})
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// 4. Username-first multi-step flow (Google/Microsoft-style): password field
	//    is revealed only after the "Next" button.
	e.GET("/auth/multistep-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, multiStepLoginPage)
	})

	// 5. Disabled-until-valid submit button — a real regression class: the submit
	//    stays disabled until JS marks the form valid, so a naive immediate click
	//    hangs. The engine must settle/fall back to Enter.
	e.GET("/auth/strict-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, strictLoginPage)
	})

	// 6. SPA login that stores a JWT in localStorage (no cookie at all).
	e.GET("/auth/spa-token-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, spaTokenLoginPage)
	})

	// 7. OAuth-style redirect flow: authorize -> (auto consent) -> callback sets
	//    the session and redirects to the dashboard.
	e.GET("/auth/oauth/authorize", func(c echo.Context) error {
		return c.Redirect(http.StatusFound, "/auth/oauth/callback?code="+randToken())
	})
	e.GET("/auth/oauth/callback", func(c echo.Context) error {
		if c.QueryParam("code") == "" {
			return c.String(http.StatusBadRequest, "missing code")
		}
		session, _ := st.issue(AuthUsername)
		setSessionCookie(c, session)
		return c.Redirect(http.StatusFound, "/auth/dashboard")
	})

	// 8. Multi-form page: a decoy search form (no password) precedes the real
	//    login form. The detector must score forms and pick the credential one
	//    rather than blindly taking the first <form>.
	e.GET("/auth/multiform-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, multiFormLoginPage)
	})

	// 9. JS-set cookie: login succeeds via XHR that returns the session id in the
	//    body (no Set-Cookie), and client JS writes document.cookie. The headless
	//    engine must capture cookies from the browser jar, not just Set-Cookie.
	e.GET("/auth/jscookie-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, jsCookieLoginPage)
	})
	e.POST("/auth/api/login-jsbody", func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.Bind(&body); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad request"})
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			session, _ := st.issue(AuthUsername)
			// Deliberately no Set-Cookie: the client sets the cookie via JS.
			return c.JSON(http.StatusOK, map[string]string{"session": session})
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// 10. Delayed render: the login form is injected after an async tick, so an
	//     engine that probes for the password field immediately would miss it and
	//     must wait for it to appear.
	e.GET("/auth/delayed-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, delayedLoginPage)
	})

	// 11. Header-token login: a server-rendered form whose POST returns the
	//     session token in a response header (no cookie), the token-in-header
	//     API style. The engine must read the token from the header.
	e.GET("/auth/header-token-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, headerTokenLoginPage(""))
	})
	e.POST("/auth/header-token-login", func(c echo.Context) error {
		if c.FormValue("username") == AuthUsername && c.FormValue("password") == AuthPassword {
			_, jwt := st.issue(AuthUsername)
			// Token in a header, deliberately no Set-Cookie.
			c.Response().Header().Set("X-Auth-Token", jwt)
			return c.HTML(http.StatusOK, `<html><head><title>Dashboard</title></head><body><h1>Welcome, signed in</h1></body></html>`)
		}
		return c.HTML(http.StatusOK, headerTokenLoginPage("Invalid credentials"))
	})

	// 12. SPA whose XHR login returns the token only in a response header (no
	//     cookie, no body/storage token). Exercises the headless engine's
	//     passive response-header interception.
	e.GET("/auth/spa-header-token-login", func(c echo.Context) error {
		return c.HTML(http.StatusOK, spaHeaderTokenLoginPage)
	})
	e.POST("/auth/api/login-header", func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.Bind(&body); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad request"})
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			_, jwt := st.issue(AuthUsername)
			c.Response().Header().Set("X-Auth-Token", jwt)
			return c.JSON(http.StatusOK, map[string]bool{"ok": true})
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// Protected landing page: the login-success heuristic relies on the final
	// page having no password field, which this page satisfies.
	e.GET("/auth/dashboard", func(c echo.Context) error {
		user, ok := st.authenticatedUser(c)
		if !ok {
			return c.Redirect(http.StatusFound, "/auth/form-login")
		}
		return c.HTML(http.StatusOK, fmt.Sprintf(`<html><head><title>Dashboard</title></head>
<body><h1>Welcome, %s</h1><a href="/auth/logout">Logout</a></body></html>`, html.EscapeString(user)))
	})

	// whoami: protected API used to assert a captured session authenticates.
	e.GET("/auth/whoami", func(c echo.Context) error {
		user, ok := st.authenticatedUser(c)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}
		return c.JSON(http.StatusOK, map[string]string{"user": user})
	})

	// Authenticated, fuzzable endpoint: only reachable with a valid session, and
	// reflects q without sanitization (reflected XSS) so authenticated fuzzing
	// has a genuine target behind the login wall.
	e.GET("/auth/api/search", func(c echo.Context) error {
		if _, ok := st.authenticatedUser(c); !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}
		q := c.QueryParam("q")
		return c.HTML(http.StatusOK, fmt.Sprintf("<html><body><div>results for: %s</div></body></html>", q))
	})

	e.GET("/auth/logout", func(c echo.Context) error {
		ctx := c
		if ck, err := ctx.Cookie(authSessionCookie); err == nil {
			st.mu.Lock()
			delete(st.sessions, ck.Value)
			st.mu.Unlock()
		}
		setSessionCookie(c, "")
		return c.Redirect(http.StatusFound, "/auth/form-login")
	})
}

// --- Login page templates --------------------------------------------------

func formLoginPage(username, errMsg string) string {
	var banner string
	if errMsg != "" {
		banner = fmt.Sprintf(`<p class="error">%s</p>`, html.EscapeString(errMsg))
	}
	return fmt.Sprintf(`<html><head><title>Login</title></head><body>
<h1>Sign in</h1>%s
<form method="post" action="/auth/form-login">
  <input type="text" name="username" placeholder="Email" value="%s">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign in</button>
</form></body></html>`, banner, html.EscapeString(username))
}

func csrfLoginPage(csrf, errMsg string) string {
	var banner string
	if errMsg != "" {
		banner = fmt.Sprintf(`<p class="error">%s</p>`, html.EscapeString(errMsg))
	}
	return fmt.Sprintf(`<html><head><title>Login</title></head><body>
<h1>Sign in</h1>%s
<form method="post" action="/auth/csrf-login">
  <input type="hidden" name="csrf_token" value="%s">
  <input type="text" name="username" placeholder="Email">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign in</button>
</form></body></html>`, banner, html.EscapeString(csrf))
}

// spaLoginPage builds the form entirely in JS (no <form> in the raw HTML) and
// submits it via fetch, then redirects on success.
const spaLoginPage = `<html><head><title>SPA Login</title></head><body>
<div id="app"></div>
<script>
  var app = document.getElementById('app');
  var email = document.createElement('input'); email.id = 'email'; email.type = 'email';
  var pass = document.createElement('input'); pass.id = 'password'; pass.type = 'password';
  var btn = document.createElement('button'); btn.id = 'submit'; btn.textContent = 'Sign in';
  app.appendChild(email); app.appendChild(pass); app.appendChild(btn);
  btn.addEventListener('click', function () {
    fetch('/auth/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: email.value, password: pass.value})
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.token) { document.body.innerHTML = '<h1>Welcome, signed in</h1>'; }
      else { document.body.innerHTML += '<p>login failed</p>'; }
    });
  });
</script></body></html>`

// multiStepLoginPage hides the password field until "Next" is clicked.
const multiStepLoginPage = `<html><head><title>Multi-step Login</title></head><body>
<form id="f" method="post" action="/auth/form-login">
  <input type="text" name="username" id="username" placeholder="Email">
  <button type="button" id="next">Next</button>
  <div id="pwwrap" style="display:none">
    <input type="password" name="password" id="password" placeholder="Password">
    <button type="submit" id="submit">Sign in</button>
  </div>
</form>
<script>
  document.getElementById('next').addEventListener('click', function () {
    document.getElementById('pwwrap').style.display = 'block';
  });
</script></body></html>`

// strictLoginPage keeps the submit button disabled until both fields are
// non-empty, reproducing the disabled-until-valid regression class.
const strictLoginPage = `<html><head><title>Strict Login</title></head><body>
<form method="post" action="/auth/form-login">
  <input type="text" name="username" id="username" placeholder="Email">
  <input type="password" name="password" id="password" placeholder="Password">
  <button type="submit" id="submit" disabled>Sign in</button>
</form>
<script>
  var u = document.getElementById('username'), p = document.getElementById('password'), b = document.getElementById('submit');
  function validate() { b.disabled = !(u.value.length > 0 && p.value.length > 0); }
  u.addEventListener('input', validate); p.addEventListener('input', validate);
</script></body></html>`

// spaTokenLoginPage validates client-side and stores a JWT in localStorage with
// no cookie, the canonical token-in-web-storage case.
var spaTokenLoginPage = fmt.Sprintf(`<html><head><title>SPA Token Login</title></head><body>
<form id="f">
  <input type="email" name="username" id="email" placeholder="Email">
  <input type="password" name="password" id="password" placeholder="Password">
  <button type="submit" id="submit">Sign in</button>
</form>
<script>
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var u = document.getElementById('email').value;
    var p = document.getElementById('password').value;
    if (u === %q && p === %q) {
      window.localStorage.setItem('access_token', %q);
      window.sessionStorage.setItem('uid', '1');
      document.body.innerHTML = '<h1>Welcome, signed in</h1>';
    } else {
      document.body.innerHTML += '<p>login failed</p>';
    }
  });
</script></body></html>`, AuthUsername, AuthPassword, jwtFor("spa-static-session"))

// multiFormLoginPage places a decoy search form (no password field) before the
// real login form to exercise best-form selection over first-form selection.
const multiFormLoginPage = `<html><head><title>Multi-form Login</title></head><body>
<form id="search" method="get" action="/auth/api/search">
  <input type="text" name="q" placeholder="Search">
  <button type="submit">Search</button>
</form>
<hr>
<form id="login" method="post" action="/auth/form-login">
  <input type="text" name="username" placeholder="Email">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign in</button>
</form></body></html>`

// jsCookieLoginPage logs in via XHR and sets the session cookie from JS
// (document.cookie) rather than relying on a Set-Cookie response header.
const jsCookieLoginPage = `<html><head><title>JS Cookie Login</title></head><body>
<form id="f">
  <input type="email" name="username" id="email" placeholder="Email">
  <input type="password" name="password" id="password" placeholder="Password">
  <button type="submit" id="submit">Sign in</button>
</form>
<script>
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    fetch('/auth/api/login-jsbody', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('email').value,
        password: document.getElementById('password').value
      })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.session) {
        document.cookie = 'PSESSION=' + d.session + '; path=/';
        document.body.innerHTML = '<h1>Welcome, signed in</h1>';
      } else {
        document.body.innerHTML += '<p>login failed</p>';
      }
    });
  });
</script></body></html>`

// headerTokenLoginPage is a classic server-rendered form whose POST returns the
// session token in a response header rather than a cookie or body.
func headerTokenLoginPage(errMsg string) string {
	var banner string
	if errMsg != "" {
		banner = fmt.Sprintf(`<p class="error">%s</p>`, html.EscapeString(errMsg))
	}
	return fmt.Sprintf(`<html><head><title>Header Token Login</title></head><body>
<h1>Sign in</h1>%s
<form method="post" action="/auth/header-token-login">
  <input type="text" name="username" placeholder="Email">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign in</button>
</form></body></html>`, banner)
}

// spaHeaderTokenLoginPage logs in via XHR; the token comes back only in a
// response header (the page never reads or stores it), so the session is
// recoverable only by observing response headers.
const spaHeaderTokenLoginPage = `<html><head><title>SPA Header Token Login</title></head><body>
<form id="f">
  <input type="email" name="username" id="email" placeholder="Email">
  <input type="password" name="password" id="password" placeholder="Password">
  <button type="submit" id="submit">Sign in</button>
</form>
<script>
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    fetch('/auth/api/login-header', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('email').value,
        password: document.getElementById('password').value
      })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.ok) { document.body.innerHTML = '<h1>Welcome, signed in</h1>'; }
      else { document.body.innerHTML += '<p>login failed</p>'; }
    });
  });
</script></body></html>`

// delayedLoginPage injects the login form only after an async tick, simulating a
// SPA that renders its form after bootstrapping.
const delayedLoginPage = `<html><head><title>Delayed Login</title></head><body>
<div id="app"><p>loading...</p></div>
<script>
  setTimeout(function () {
    document.getElementById('app').innerHTML =
      '<form method="post" action="/auth/form-login">' +
      '<input type="text" name="username" placeholder="Email">' +
      '<input type="password" name="password" placeholder="Password">' +
      '<button type="submit">Sign in</button></form>';
  }, 700);
</script></body></html>`
