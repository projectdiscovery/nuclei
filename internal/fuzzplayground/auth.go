package fuzzplayground

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
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
func (s *authStore) authenticatedUser(r *http.Request) (string, bool) {
	if c, err := r.Cookie(authSessionCookie); err == nil && c.Value != "" {
		if u, ok := s.userFor(c.Value); ok {
			return u, true
		}
	}
	auth := r.Header.Get("Authorization")
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

func setSessionCookie(w http.ResponseWriter, session string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookie,
		Value:    session,
		Path:     "/",
		HttpOnly: true,
	})
}

// registerAuthRoutes wires every login style and the protected endpoints onto a
// per-server auth store.
func registerAuthRoutes(mux *http.ServeMux) {
	st := newAuthStore()

	// 1. Classic server-rendered form login (works with the static HTTP engine).
	mux.HandleFunc("GET /auth/form-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, formLoginPage("", ""))
	})
	mux.HandleFunc("POST /auth/form-login", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") == AuthUsername && r.FormValue("password") == AuthPassword {
			session, _ := st.issue(AuthUsername)
			setSessionCookie(w, session)
			http.Redirect(w, r, "/auth/dashboard", http.StatusFound)
			return
		}
		writeHTML(w, http.StatusOK, formLoginPage(r.FormValue("username"), "Invalid credentials"))
	})

	// 2. CSRF-protected server-rendered form: a hidden token must be echoed back.
	mux.HandleFunc("GET /auth/csrf-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, csrfLoginPage(st.issueCSRF(), ""))
	})
	mux.HandleFunc("POST /auth/csrf-login", func(w http.ResponseWriter, r *http.Request) {
		if !st.consumeCSRF(r.FormValue("csrf_token")) {
			writeHTML(w, http.StatusForbidden, csrfLoginPage(st.issueCSRF(), "Invalid CSRF token"))
			return
		}
		if r.FormValue("username") == AuthUsername && r.FormValue("password") == AuthPassword {
			session, _ := st.issue(AuthUsername)
			setSessionCookie(w, session)
			http.Redirect(w, r, "/auth/dashboard", http.StatusFound)
			return
		}
		writeHTML(w, http.StatusOK, csrfLoginPage(st.issueCSRF(), "Invalid credentials"))
	})

	// 3. JS/SPA-rendered form: the raw HTML has no <form>; JS builds it and posts
	//    via fetch. Only a real browser can log in here.
	mux.HandleFunc("GET /auth/spa-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, spaLoginPage)
	})
	mux.HandleFunc("POST /auth/api/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			session, jwt := st.issue(AuthUsername)
			setSessionCookie(w, session)
			writeJSON(w, http.StatusOK, map[string]string{"token": jwt})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// 4. Username-first multi-step flow (Google/Microsoft-style): password field
	//    is revealed only after the "Next" button.
	mux.HandleFunc("GET /auth/multistep-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, multiStepLoginPage)
	})

	// 5. Disabled-until-valid submit button — a real regression class: the submit
	//    stays disabled until JS marks the form valid, so a naive immediate click
	//    hangs. The engine must settle/fall back to Enter.
	mux.HandleFunc("GET /auth/strict-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, strictLoginPage)
	})

	// 6. SPA login that stores a JWT in localStorage (no cookie at all).
	mux.HandleFunc("GET /auth/spa-token-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, spaTokenLoginPage)
	})

	// 7. OAuth-style redirect flow: authorize -> (auto consent) -> callback sets
	//    the session and redirects to the dashboard.
	mux.HandleFunc("GET /auth/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/oauth/callback?code="+randToken(), http.StatusFound)
	})
	mux.HandleFunc("GET /auth/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") == "" {
			writeString(w, http.StatusBadRequest, "missing code")
			return
		}
		session, _ := st.issue(AuthUsername)
		setSessionCookie(w, session)
		http.Redirect(w, r, "/auth/dashboard", http.StatusFound)
	})

	// 8. Multi-form page: a decoy search form (no password) precedes the real
	//    login form. The detector must score forms and pick the credential one
	//    rather than blindly taking the first <form>.
	mux.HandleFunc("GET /auth/multiform-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, multiFormLoginPage)
	})

	// 9. JS-set cookie: login succeeds via XHR that returns the session id in the
	//    body (no Set-Cookie), and client JS writes document.cookie. The headless
	//    engine must capture cookies from the browser jar, not just Set-Cookie.
	mux.HandleFunc("GET /auth/jscookie-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, jsCookieLoginPage)
	})
	mux.HandleFunc("POST /auth/api/login-jsbody", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			session, _ := st.issue(AuthUsername)
			// Deliberately no Set-Cookie: the client sets the cookie via JS.
			writeJSON(w, http.StatusOK, map[string]string{"session": session})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// 10. Delayed render: the login form is injected after an async tick, so an
	//     engine that probes for the password field immediately would miss it and
	//     must wait for it to appear.
	mux.HandleFunc("GET /auth/delayed-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, delayedLoginPage)
	})

	// 11. Header-token login: a server-rendered form whose POST returns the
	//     session token in a response header (no cookie), the token-in-header
	//     API style. The engine must read the token from the header.
	mux.HandleFunc("GET /auth/header-token-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, headerTokenLoginPage(""))
	})
	mux.HandleFunc("POST /auth/header-token-login", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") == AuthUsername && r.FormValue("password") == AuthPassword {
			_, jwt := st.issue(AuthUsername)
			// Token in a header, deliberately no Set-Cookie.
			w.Header().Set("X-Auth-Token", jwt)
			writeHTML(w, http.StatusOK, `<html><head><title>Dashboard</title></head><body><h1>Welcome, signed in</h1></body></html>`)
			return
		}
		writeHTML(w, http.StatusOK, headerTokenLoginPage("Invalid credentials"))
	})

	// 12. SPA whose XHR login returns the token only in a response header (no
	//     cookie, no body/storage token). Exercises the headless engine's
	//     passive response-header interception.
	mux.HandleFunc("GET /auth/spa-header-token-login", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, spaHeaderTokenLoginPage)
	})
	mux.HandleFunc("POST /auth/api/login-header", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if body.Username == AuthUsername && body.Password == AuthPassword {
			_, jwt := st.issue(AuthUsername)
			w.Header().Set("X-Auth-Token", jwt)
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	})

	// Protected landing page: the login-success heuristic relies on the final
	// page having no password field, which this page satisfies.
	mux.HandleFunc("GET /auth/dashboard", func(w http.ResponseWriter, r *http.Request) {
		user, ok := st.authenticatedUser(r)
		if !ok {
			http.Redirect(w, r, "/auth/form-login", http.StatusFound)
			return
		}
		writeHTML(w, http.StatusOK, fmt.Sprintf(`<html><head><title>Dashboard</title></head>
<body><h1>Welcome, %s</h1><a href="/auth/logout">Logout</a></body></html>`, html.EscapeString(user)))
	})

	// whoami: protected API used to assert a captured session authenticates.
	mux.HandleFunc("GET /auth/whoami", func(w http.ResponseWriter, r *http.Request) {
		user, ok := st.authenticatedUser(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": user})
	})

	// Authenticated, fuzzable endpoint: only reachable with a valid session, and
	// reflects q without sanitization (reflected XSS) so authenticated fuzzing
	// has a genuine target behind the login wall.
	mux.HandleFunc("GET /auth/api/search", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := st.authenticatedUser(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		q := r.URL.Query().Get("q")
		writeHTML(w, http.StatusOK, fmt.Sprintf("<html><body><div>results for: %s</div></body></html>", q))
	})

	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie(authSessionCookie); err == nil {
			st.mu.Lock()
			delete(st.sessions, ck.Value)
			st.mu.Unlock()
		}
		setSessionCookie(w, "")
		http.Redirect(w, r, "/auth/form-login", http.StatusFound)
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
