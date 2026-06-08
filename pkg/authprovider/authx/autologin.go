package authx

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/autologin"
	"github.com/projectdiscovery/utils/errkit"
)

// AutoLoginConfig declares a turnkey, template-free authenticated-scanning
// login. Instead of pointing at a hand-written auth template (Dynamic.TemplatePath),
// the user supplies only a login URL and credentials; nuclei fetches the login
// page, auto-detects the form (username/password fields plus hidden CSRF tokens)
// and submits it, capturing the resulting session. The captured session is fed
// into the same Dynamic state machine, so refresh-interval and
// reauth-status-codes re-run the login automatically.
type AutoLoginConfig struct {
	// LoginURL is the page serving the login form (required).
	LoginURL string `json:"login-url" yaml:"login-url"`
	// Username / Password are the credentials to submit. Username may be empty
	// for password-only forms.
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	// UsernameField / PasswordField force the form field names when
	// auto-detection would guess wrong (optional).
	UsernameField string `json:"username-field" yaml:"username-field"`
	PasswordField string `json:"password-field" yaml:"password-field"`
	// ExtraFields are additional form values submitted verbatim (e.g. a tenant
	// id), overriding detected fields of the same name.
	ExtraFields []KV `json:"extra-fields" yaml:"extra-fields"`
	// TokenRegex, when set, extracts a bearer token (first capture group) from
	// the final response body for token-based logins that don't set a cookie.
	TokenRegex string `json:"token-regex" yaml:"token-regex"`

	// Headless drives a real browser for the login instead of the HTTP engine,
	// enabling JS-rendered / SPA / multi-step / SSO login pages.
	Headless bool `json:"headless" yaml:"headless"`
	// ShowBrowser runs the headless browser headful (debugging only).
	ShowBrowser bool `json:"show-browser" yaml:"show-browser"`
	// UseInstalledChrome forces a system-installed Chrome for the headless login.
	UseInstalledChrome bool `json:"use-installed-chrome" yaml:"use-installed-chrome"`
	// Proxy routes the headless login's browser traffic through this proxy URL.
	Proxy string `json:"proxy" yaml:"proxy"`
	// Steps, when set, drives an explicit multi-step headless login flow
	// (username-first / SSO / consent screens) instead of single-shot detection.
	Steps []autologin.LoginStep `json:"steps" yaml:"steps"`
}

// Validate validates the auto-login configuration.
func (a *AutoLoginConfig) Validate() error {
	if a.LoginURL == "" {
		return errkit.New("login-url is required for auto-login dynamic secret")
	}
	if a.Password == "" {
		return errkit.New("password is required for auto-login dynamic secret")
	}
	return nil
}

// AutoLoginRuntimeOptions carries scan-level browser configuration (from
// types.Options) into the auto-login engine so a headless login uses the same
// identity (user-agent, headers), network path (proxy, CDP endpoint) and Chrome
// settings as the scan. Per-secret YAML fields take precedence over these.
type AutoLoginRuntimeOptions struct {
	HTTPClient         *http.Client
	UserAgent          string
	CustomHeaders      map[string]string
	Proxy              string
	CDPEndpoint        string
	UseInstalledChrome bool
	ShowBrowser        bool
}

// SetAutoLoginCallback installs the fetch callback that performs the form-based
// auto-login and renders the captured session into the secret. Unlike
// SetLazyFetchCallback, it does not run the template-substitution wrapper: the
// applied secret is built directly from the captured cookies/token, so it is
// simply overwritten on each (re-)authentication.
//
// rt carries optional scan-level browser/runtime options (user-agent, headers,
// proxy, CDP endpoint, HTTP client); pass nil for defaults.
func (d *Dynamic) SetAutoLoginCallback(rt *AutoLoginRuntimeOptions) {
	if rt == nil {
		rt = &AutoLoginRuntimeOptions{}
	}
	d.autoLoginClient = rt.HTTPClient
	d.fetchCallback = func(d *Dynamic) error {
		if d.AutoLogin == nil {
			return errkit.New("auto-login callback invoked without auto-login config")
		}
		cfg := autologin.Config{
			LoginURL:           d.AutoLogin.LoginURL,
			Username:           d.AutoLogin.Username,
			Password:           d.AutoLogin.Password,
			UsernameField:      d.AutoLogin.UsernameField,
			PasswordField:      d.AutoLogin.PasswordField,
			TokenRegex:         d.AutoLogin.TokenRegex,
			ExtraFields:        kvSliceToMap(d.AutoLogin.ExtraFields),
			Headless:           d.AutoLogin.Headless,
			ShowBrowser:        d.AutoLogin.ShowBrowser || rt.ShowBrowser,
			UseInstalledChrome: d.AutoLogin.UseInstalledChrome || rt.UseInstalledChrome,
			Proxy:              firstNonEmpty(d.AutoLogin.Proxy, rt.Proxy),
			CDPEndpoint:        rt.CDPEndpoint,
			UserAgent:          rt.UserAgent,
			CustomHeaders:      rt.CustomHeaders,
			Steps:              d.AutoLogin.Steps,
		}
		var (
			session *autologin.Session
			err     error
		)
		engine := autoLoginEngineName(d.AutoLogin.Headless)
		if d.AutoLogin.Headless {
			// The browser engine runs JS, so it handles SPA / multi-step / SSO
			// login pages the HTTP form submitter cannot.
			session, err = autologin.LoginHeadless(context.Background(), cfg)
		} else {
			session, err = autologin.Login(context.Background(), d.autoLoginClient, cfg)
		}
		if err != nil {
			// Surface a clear, actionable failure at scan start (prefetch) and on
			// every lazy re-authentication.
			gologger.Warning().Msgf("auto-login (%s) failed for %s: %s", engine, cfg.LoginURL, err)
			return errkit.Wrapf(err, "auto-login (%s) failed for %s", engine, cfg.LoginURL)
		}

		// Expose extracted values for observability / downstream templating.
		d.Extracted = map[string]interface{}{}
		if session.CookieHeader != "" {
			d.Extracted["cookie"] = session.CookieHeader
		}
		for _, c := range session.Cookies {
			d.Extracted[c.Name] = c.Value
		}
		if session.Token != "" {
			d.Extracted["token"] = session.Token
		}

		if applyErr := d.applyAutoLoginSession(session); applyErr != nil {
			gologger.Warning().Msgf("auto-login (%s) for %s: %s", engine, cfg.LoginURL, applyErr)
			return errkit.Wrapf(applyErr, "auto-login (%s) for %s", engine, cfg.LoginURL)
		}
		gologger.Info().Msgf("auto-login (%s) succeeded for %s: %s", engine, cfg.LoginURL, summarizeSession(session))
		return nil
	}
}

// autoLoginEngineName returns a human-readable engine label for log messages.
func autoLoginEngineName(headless bool) string {
	if headless {
		return "headless"
	}
	return "http"
}

// summarizeSession produces a concise human-readable summary of what an
// auto-login captured, for the success log line.
func summarizeSession(session *autologin.Session) string {
	if session == nil {
		return "no session"
	}
	var parts []string
	if n := len(session.Cookies); n > 0 {
		parts = append(parts, fmt.Sprintf("%d cookie(s)", n))
	}
	if session.Token != "" {
		parts = append(parts, "bearer token")
	}
	if n := len(session.LocalStorage); n > 0 {
		parts = append(parts, fmt.Sprintf("%d localStorage item(s)", n))
	}
	if n := len(session.SessionStorage); n > 0 {
		parts = append(parts, fmt.Sprintf("%d sessionStorage item(s)", n))
	}
	if len(parts) == 0 {
		return "no usable session material"
	}
	return strings.Join(parts, ", ")
}

// applyAutoLoginSession builds the concrete applied secret(s) from a captured
// session. Cookies are applied as a cookie secret; an extracted token is applied
// as a bearer header. When both are present (common for SPAs that set a session
// cookie *and* a localStorage JWT) both are applied. The applied fields are
// reset first so a re-authentication fully replaces the previous session.
func (d *Dynamic) applyAutoLoginSession(session *autologin.Session) error {
	if d.Secret == nil {
		d.Secret = &Secret{}
	}
	// Reset previously applied auth so re-auth replaces (not appends to) it.
	d.Secret.Headers = nil
	d.Secret.Cookies = nil
	d.Secret.Token = ""
	d.Secrets = nil

	// Stash captured web storage (headless logins only) on the shared fetchState
	// so the headless engine can replay it into scan pages. Reset each re-auth.
	if d.fetchState != nil {
		d.fetchState.webStorageLocal = session.LocalStorage
		d.fetchState.webStorageSession = session.SessionStorage
	}

	hasCookies := len(session.Cookies) > 0
	hasToken := session.Token != ""
	hasStorage := len(session.LocalStorage) > 0 || len(session.SessionStorage) > 0
	if !hasCookies && !hasToken && !hasStorage {
		return errkit.New("auto-login produced no applicable session (no cookies, token or web storage)")
	}
	if !hasCookies && !hasToken {
		// Storage-only session (e.g. a pure localStorage-JWT SPA): there is no
		// HTTP-applicable secret, but the headless engine will replay the storage.
		// Leave the secret type empty so it yields no HTTP strategy.
		d.Secret.Type = ""
		return nil
	}

	switch {
	case hasCookies:
		d.Secret.Type = string(CookiesAuth)
		for _, c := range session.Cookies {
			d.Secret.Cookies = append(d.Secret.Cookies, Cookie{Key: c.Name, Value: c.Value})
		}
		if hasToken {
			// Apply the token as an additional bearer header secret.
			d.Secrets = append(d.Secrets, &Secret{
				Type:    string(BearerTokenAuth),
				Domains: d.Secret.Domains,
				Token:   session.Token,
			})
		}
	default: // token only
		d.Secret.Type = string(BearerTokenAuth)
		d.Secret.Token = session.Token
	}
	return nil
}

// firstNonEmpty returns the first non-empty string argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// kvSliceToMap converts a slice of KV pairs to a map for the autologin engine.
func kvSliceToMap(kvs []KV) map[string]string {
	if len(kvs) == 0 {
		return nil
	}
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	return m
}
