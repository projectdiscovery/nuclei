package authx

import (
	"context"
	"net/http"

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

// SetAutoLoginCallback installs the fetch callback that performs the form-based
// auto-login and renders the captured session into the secret. Unlike
// SetLazyFetchCallback, it does not run the template-substitution wrapper: the
// applied secret is built directly from the captured cookies/token, so it is
// simply overwritten on each (re-)authentication.
//
// client is an optional template HTTP client whose Transport (proxy/TLS) is
// reused for the login requests; pass nil for defaults.
func (d *Dynamic) SetAutoLoginCallback(client *http.Client) {
	d.autoLoginClient = client
	d.fetchCallback = func(d *Dynamic) error {
		if d.AutoLogin == nil {
			return errkit.New("auto-login callback invoked without auto-login config")
		}
		cfg := autologin.Config{
			LoginURL:      d.AutoLogin.LoginURL,
			Username:      d.AutoLogin.Username,
			Password:      d.AutoLogin.Password,
			UsernameField: d.AutoLogin.UsernameField,
			PasswordField: d.AutoLogin.PasswordField,
			TokenRegex:    d.AutoLogin.TokenRegex,
			ExtraFields:   kvSliceToMap(d.AutoLogin.ExtraFields),
		}
		session, err := autologin.Login(context.Background(), d.autoLoginClient, cfg)
		if err != nil {
			return err
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

		return d.applyAutoLoginSession(session)
	}
}

// applyAutoLoginSession builds the concrete applied secret from a captured
// session. Cookies take precedence (the common form-login case); a bare token
// is applied as bearer auth. The applied fields are reset first so a
// re-authentication fully replaces the previous session.
func (d *Dynamic) applyAutoLoginSession(session *autologin.Session) error {
	if d.Secret == nil {
		d.Secret = &Secret{}
	}
	// Reset previously applied auth so re-auth replaces (not appends to) it.
	d.Secret.Headers = nil
	d.Secret.Cookies = nil
	d.Secret.Token = ""

	switch {
	case len(session.Cookies) > 0:
		d.Secret.Type = string(CookiesAuth)
		for _, c := range session.Cookies {
			d.Secret.Cookies = append(d.Secret.Cookies, Cookie{Key: c.Name, Value: c.Value})
		}
	case session.Token != "":
		d.Secret.Type = string(BearerTokenAuth)
		d.Secret.Token = session.Token
	default:
		return errkit.New("auto-login produced no applicable session (no cookies or token)")
	}
	return nil
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
