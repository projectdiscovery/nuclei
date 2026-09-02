package autologin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/fuzzplayground"
	"github.com/stretchr/testify/require"
)

// playgroundServer starts the in-repo auth playground and returns its base URL.
func playgroundServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(fuzzplayground.GetPlaygroundServer())
	t.Cleanup(srv.Close)
	return srv.URL
}

// assertSessionAuthenticates verifies a captured session actually authenticates
// against the playground's protected /auth/whoami endpoint, trying both the
// cookie and bearer-token representations.
func assertSessionAuthenticates(t *testing.T, base string, s *Session) {
	t.Helper()
	apply := func(req *http.Request) {
		if s.CookieHeader != "" {
			req.Header.Set("Cookie", s.CookieHeader)
		}
		if s.Token != "" {
			req.Header.Set("Authorization", "Bearer "+s.Token)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/auth/whoami", nil)
	apply(req)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "whoami should accept the captured session; body=%s", body)
	require.Contains(t, string(body), fuzzplayground.AuthUsername, "whoami should identify the logged-in user")
}

func cookieNames(s *Session) map[string]string {
	out := map[string]string{}
	for _, c := range s.Cookies {
		out[c.Name] = c.Value
	}
	return out
}

// --- HTTP engine styles ----------------------------------------------------

func TestPlayground_HTTPFormLogin(t *testing.T) {
	base := playgroundServer(t)
	session, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/form-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION", "form login should set a session cookie")
	assertSessionAuthenticates(t, base, session)
}

func TestPlayground_HTTPCSRFLogin(t *testing.T) {
	base := playgroundServer(t)
	session, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/csrf-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.NoError(t, err, "HTTP engine must capture and replay the hidden CSRF token")
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

func TestPlayground_HTTPWrongPasswordFails(t *testing.T) {
	base := playgroundServer(t)
	_, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/form-login",
		Username: fuzzplayground.AuthUsername,
		Password: "wrong",
	})
	require.ErrorIs(t, err, ErrLoginFailed)
}

// TestPlayground_HTTPHeaderTokenLogin proves the HTTP engine extracts a session
// token delivered in a response header (no cookie, no body token).
func TestPlayground_HTTPHeaderTokenLogin(t *testing.T) {
	base := playgroundServer(t)
	session, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/header-token-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.NoError(t, err, "the engine must extract the token from the response header")
	require.Empty(t, session.Cookies, "header-token login sets no cookie")
	require.NotEmpty(t, session.Token, "token must be read from the X-Auth-Token header")
	assertSessionAuthenticates(t, base, session)
}

// --- Headless styles -------------------------------------------------------

func TestPlayground_HeadlessSPALogin(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The static HTTP engine cannot log in here (the form is built by JS).
	_, httpErr := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/spa-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.ErrorIs(t, httpErr, ErrNoLoginForm)

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/spa-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

func TestPlayground_HeadlessMultiStep(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/multistep-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1 * time.Second,
		Steps: []LoginStep{
			{Action: "fill", Selector: "#username", Value: "{{username}}"},
			{Action: "click", Selector: "#next"},
			{Action: "waitvisible", Selector: "#password"},
			{Action: "fill", Selector: "#password", Value: "{{password}}"},
			{Action: "click", Selector: "#submit"},
		},
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HeadlessStrictSubmit is the regression for the disabled-until-
// valid submit button: the engine must settle (so JS enables the button) and/or
// fall back to Enter rather than hang on the disabled control.
func TestPlayground_HeadlessStrictSubmit(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/strict-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

func TestPlayground_HeadlessSPAToken(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/spa-token-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		TokenRegex: `(eyJ[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)`,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Empty(t, session.Cookies, "SPA-token login sets no cookie")
	require.NotEmpty(t, session.Token, "token must be extracted from localStorage")
	require.NotEmpty(t, session.LocalStorage["access_token"], "localStorage must be captured")
	// The captured bearer token must authenticate the protected API.
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HeadlessSPATokenAutoDetect proves the engine surfaces a JWT
// kept in web storage as the session token even when no token-regex is given
// (the JWT is stored under the conventional "access_token" key).
func TestPlayground_HeadlessSPATokenAutoDetect(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/spa-token-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1500 * time.Millisecond,
		// Intentionally no TokenRegex: rely on web-storage JWT auto-detection.
	})
	require.NoError(t, err)
	require.NotEmpty(t, session.Token, "JWT in localStorage must be auto-detected without a token-regex")
	require.NotEmpty(t, session.LocalStorage["access_token"], "localStorage must be captured")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HTTPMultiFormPicksLogin proves the form detector selects the
// credential form on a page that also contains a decoy search form (no
// password), rather than blindly taking the first <form>.
func TestPlayground_HTTPMultiFormPicksLogin(t *testing.T) {
	base := playgroundServer(t)
	session, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/multiform-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.NoError(t, err, "detector must pick the login form over the decoy search form")
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HeadlessJSCookieLogin proves cookies set client-side via
// document.cookie (no Set-Cookie header) are captured from the browser jar.
func TestPlayground_HeadlessJSCookieLogin(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/jscookie-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION", "JS-set cookie must be captured from the browser")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HeadlessDelayedFormLogin proves the engine waits for a login
// form that is injected asynchronously instead of failing immediately.
func TestPlayground_HeadlessDelayedFormLogin(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/delayed-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 2 * time.Second,
	})
	require.NoError(t, err, "engine must wait for the asynchronously-rendered form")
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_HeadlessHeaderTokenLogin proves the headless engine recovers a
// token that is only ever delivered in an XHR response header (never stored in
// a cookie or web storage) via passive response-header interception.
func TestPlayground_HeadlessHeaderTokenLogin(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/spa-header-token-login",
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Empty(t, session.Cookies, "header-token SPA sets no cookie")
	require.Empty(t, session.LocalStorage["token"], "the SPA does not store the token")
	require.NotEmpty(t, session.Token, "token must be captured from the XHR response header")
	assertSessionAuthenticates(t, base, session)
}

func TestPlayground_HeadlessOAuthRedirect(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Pure redirect SSO: visiting authorize logs the user in; there is no form,
	// so a single settle step lets the redirect chain complete before capture.
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   base + "/auth/oauth/authorize",
		SettleTime: 1 * time.Second,
		Steps:      []LoginStep{{Action: "wait", Value: "1s"}},
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

// TestPlayground_RecordingReplay imports a Chrome Recorder export (with the base
// URL templated in), verifies the recorded credential literals are parameterized
// out, and replays the compiled steps headlessly to obtain a real session.
func TestPlayground_RecordingReplay(t *testing.T) {
	requireChrome(t)
	base := playgroundServer(t)

	raw, err := os.ReadFile(filepath.Join("testdata", "recordings", "spa_login.json"))
	require.NoError(t, err)
	rec := strings.ReplaceAll(string(raw), "__BASE__", base)
	recFile := filepath.Join(t.TempDir(), "spa_login.json")
	require.NoError(t, os.WriteFile(recFile, []byte(rec), 0o600))

	steps, err := StepsFromRecordingFile(recFile, fuzzplayground.AuthUsername, fuzzplayground.AuthPassword)
	require.NoError(t, err)
	// Credentials must never survive in the compiled steps.
	for _, s := range steps {
		require.NotContains(t, s.Value, fuzzplayground.AuthPassword, "password literal leaked into steps")
		require.NotContains(t, s.Value, fuzzplayground.AuthUsername, "username literal leaked into steps")
	}
	require.Contains(t, stepValues(steps), "{{username}}")
	require.Contains(t, stepValues(steps), "{{password}}")
	// An xpath-only selector must compile to the engine's xpath= form.
	require.Contains(t, stepSelectors(steps), "xpath=//input[@id='email']")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   FirstNavigateURL(steps),
		Username:   fuzzplayground.AuthUsername,
		Password:   fuzzplayground.AuthPassword,
		Steps:      steps,
		SettleTime: 1500 * time.Millisecond,
	})
	require.NoError(t, err)
	require.Contains(t, cookieNames(session), "PSESSION")
	assertSessionAuthenticates(t, base, session)
}

func stepValues(steps []LoginStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Value)
	}
	return out
}

func stepSelectors(steps []LoginStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Selector)
	}
	return out
}

// --- Authenticated fuzzing target -----------------------------------------

// TestPlayground_AuthenticatedEndpointBehindLogin proves the authenticated,
// fuzzable endpoint is only reachable with a captured session and reflects input
// (a genuine target behind the login wall for authenticated scanning).
func TestPlayground_AuthenticatedEndpointBehindLogin(t *testing.T) {
	base := playgroundServer(t)
	session, err := Login(context.Background(), nil, Config{
		LoginURL: base + "/auth/form-login",
		Username: fuzzplayground.AuthUsername,
		Password: fuzzplayground.AuthPassword,
	})
	require.NoError(t, err)

	// Unauthenticated: blocked.
	resp, err := http.Get(base + "/auth/api/search?q=hello")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "search must require auth")

	// Authenticated: reachable and reflects the payload unsanitized.
	req, _ := http.NewRequest(http.MethodGet, base+"/auth/api/search?q="+payloadXSS, nil)
	req.Header.Set("Cookie", session.CookieHeader)
	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	body, _ := io.ReadAll(resp2.Body)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.True(t, strings.Contains(string(body), payloadXSS), "authenticated endpoint should reflect the payload")
}

const payloadXSS = "<script>alert(1)</script>"
