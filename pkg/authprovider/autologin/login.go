package autologin

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// maxBodyRead caps how much of the login/landing page we read into memory for
// form detection and success checks.
const maxBodyRead = 4 << 20 // 4MB

var (
	// ErrLoginFailed is returned when the login flow completed but produced no
	// usable session (no cookies, no token) — typically wrong credentials.
	ErrLoginFailed = errkit.New("auto-login produced no session (check credentials)")
)

// Config describes a single auto-login attempt.
type Config struct {
	// LoginURL is the page that serves the login form (required).
	LoginURL string
	// Username / Password are the credentials to submit. Username may be empty
	// for password-only forms.
	Username string
	Password string

	// The following are optional overrides for cases where auto-detection would
	// guess wrong.

	// UsernameField forces the form field name that receives the username.
	UsernameField string
	// PasswordField forces the form field name that receives the password.
	PasswordField string
	// ExtraFields are additional form values submitted verbatim; they override
	// any detected field of the same name (e.g. a fixed TOTP or tenant id).
	ExtraFields map[string]string
	// TokenRegex, when set, is applied to the final response body to extract a
	// bearer/session token (first capture group). This enables token-based
	// logins that return the token in the response body rather than a cookie.
	// For headless logins it is also matched against window.localStorage.
	TokenRegex string
	// Timeout bounds the whole login flow. Defaults to 30s when zero.
	Timeout time.Duration

	// The following fields apply only to the headless engine (LoginHeadless).

	// Headless drives a real browser (go-rod) instead of the HTTP engine,
	// enabling JS-rendered / SPA / multi-step login pages.
	Headless bool
	// ShowBrowser runs the browser headful (useful for debugging).
	ShowBrowser bool
	// UseInstalledChrome forces using a system-installed Chrome binary.
	UseInstalledChrome bool
	// Proxy routes browser traffic through the given proxy URL.
	Proxy string
	// ChromeWSURL connects to an existing browser over CDP instead of launching one.
	ChromeWSURL string
	// SettleTime is how long to wait for the post-submit navigation / SPA to
	// settle before capturing the session. Defaults to 5s.
	SettleTime time.Duration
}

// Session is the captured result of a successful auto-login.
type Session struct {
	// Cookies are the session cookies captured after login (name/value only).
	Cookies []*http.Cookie
	// CookieHeader is the cookies rendered as a single "k=v; k2=v2" header value.
	CookieHeader string
	// Token is a token extracted via Config.TokenRegex, if any.
	Token string
	// FinalURL / FinalStatus describe where the login flow landed.
	FinalURL    string
	FinalStatus int
}

// Login performs a form-based auto-login: it fetches the login page, detects the
// login form, submits the supplied credentials (carrying any hidden CSRF tokens
// and the cookie jar), follows redirects and captures the resulting session.
//
// base is an optional template client whose Transport is reused (for proxy/TLS
// settings); its cookie jar and redirect policy are intentionally NOT reused so
// the login runs with a clean, dedicated jar. Pass nil to use defaults.
func Login(ctx context.Context, base *http.Client, cfg Config) (*Session, error) {
	if strings.TrimSpace(cfg.LoginURL) == "" {
		return nil, errkit.New("auto-login: login-url is required")
	}
	loginURL, err := url.Parse(cfg.LoginURL)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login: invalid login-url")
	}

	var tokenRe *regexp.Regexp
	if cfg.TokenRegex != "" {
		tokenRe, err = regexp.Compile(cfg.TokenRegex)
		if err != nil {
			return nil, errkit.Wrap(err, "auto-login: invalid token-regex")
		}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login: failed to create cookie jar")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Jar: jar, Timeout: timeout}
	if base != nil && base.Transport != nil {
		client.Transport = base.Transport
	}

	// 1. Fetch the login page (this also seeds the jar with any pre-login CSRF
	//    cookie the server sets).
	pageBody, err := doRequest(ctx, client, http.MethodGet, loginURL.String(), "", "")
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login: failed to fetch login page")
	}

	// 2. Detect the login form.
	form, err := DetectLoginForm(pageBody, loginURL)
	if err != nil {
		return nil, err
	}

	// 3. Build the submission values: detected hidden/default fields first, then
	//    the credentials, then caller overrides.
	values := url.Values{}
	for k, v := range form.Fields {
		values.Set(k, v)
	}
	userField := form.UsernameField
	if cfg.UsernameField != "" {
		userField = cfg.UsernameField
	}
	passField := form.PasswordField
	if cfg.PasswordField != "" {
		passField = cfg.PasswordField
	}
	if userField != "" {
		values.Set(userField, cfg.Username)
	}
	values.Set(passField, cfg.Password)
	for k, v := range cfg.ExtraFields {
		values.Set(k, v)
	}

	// 4. Submit the form.
	var finalBody, finalURLStr string
	var finalStatus int
	if form.Method == http.MethodGet {
		actionURL, perr := url.Parse(form.Action)
		if perr != nil {
			return nil, errkit.Wrap(perr, "auto-login: invalid form action")
		}
		q := actionURL.Query()
		for k, vs := range values {
			for _, v := range vs {
				q.Set(k, v)
			}
		}
		actionURL.RawQuery = q.Encode()
		finalBody, finalURLStr, finalStatus, err = doRequestFull(ctx, client, http.MethodGet, actionURL.String(), "", "")
	} else {
		finalBody, finalURLStr, finalStatus, err = doRequestFull(ctx, client, form.Method, form.Action, "application/x-www-form-urlencoded", values.Encode())
	}
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login: failed to submit login form")
	}

	// 5. Capture the session from the jar across the login/action/final hosts.
	session := &Session{FinalURL: finalURLStr, FinalStatus: finalStatus}
	session.Cookies = collectCookies(jar, loginURL, form.Action, finalURLStr)
	session.CookieHeader = renderCookieHeader(session.Cookies)

	if tokenRe != nil {
		if m := tokenRe.FindStringSubmatch(finalBody); len(m) > 1 {
			session.Token = m[1]
		}
	}

	// 6. Decide success.
	//
	// "Captured a cookie" is NOT a sufficient signal: servers commonly set a
	// pre-login CSRF cookie on the GET that survives a failed POST. The strongest
	// generic failure signal is being re-prompted — i.e. the page we land on
	// after submitting still presents a login form (a password field). When that
	// happens and we did not extract a token, the login failed (e.g. wrong
	// credentials). NOTE: this can misfire on apps that render a login form on
	// every page even when authenticated; such cases can use TokenRegex or field
	// overrides to disambiguate.
	if session.Token == "" {
		var finalURLParsed *url.URL
		if u, perr := url.Parse(finalURLStr); perr == nil {
			finalURLParsed = u
		}
		if _, derr := DetectLoginForm(finalBody, finalURLParsed); derr == nil {
			return nil, errkit.Wrapf(ErrLoginFailed, "still presented a login form (final status %d at %s)", finalStatus, finalURLStr)
		}
	}

	// A session must ultimately carry at least one cookie or an extracted token.
	if len(session.Cookies) == 0 && session.Token == "" {
		return nil, errkit.Wrapf(ErrLoginFailed, "final status %d at %s", finalStatus, finalURLStr)
	}
	return session, nil
}

// collectCookies gathers unique cookies the jar holds for any of the given URLs.
func collectCookies(jar http.CookieJar, loginURL *url.URL, action, final string) []*http.Cookie {
	urls := []*url.URL{loginURL}
	if u, err := url.Parse(action); err == nil {
		urls = append(urls, u)
	}
	if u, err := url.Parse(final); err == nil {
		urls = append(urls, u)
	}
	seen := map[string]bool{}
	var out []*http.Cookie
	for _, u := range urls {
		if u == nil {
			continue
		}
		for _, c := range jar.Cookies(u) {
			if seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			out = append(out, c)
		}
	}
	return out
}

// renderCookieHeader renders cookies as a single Cookie header value.
func renderCookieHeader(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// doRequest issues a request and returns only the body (used for the GET page).
func doRequest(ctx context.Context, client *http.Client, method, rawURL, contentType, body string) (string, error) {
	b, _, _, err := doRequestFull(ctx, client, method, rawURL, contentType, body)
	return b, err
}

// doRequestFull issues a request and returns the (capped) body, the final URL
// after redirects and the final status code.
func doRequestFull(ctx context.Context, client *http.Client, method, rawURL, contentType, body string) (string, string, int, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return "", "", 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return "", "", 0, err
	}
	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return string(data), finalURL, resp.StatusCode, nil
}
