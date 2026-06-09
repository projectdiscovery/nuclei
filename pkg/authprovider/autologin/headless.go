package autologin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/utils/errkit"
	osutils "github.com/projectdiscovery/utils/os"
)

// LoginHeadless performs a browser-driven auto-login using go-rod. Unlike the
// HTTP engine (Login), it executes JavaScript, so it works on SPA/JS-rendered
// login pages, client-side form construction and multi-step / SSO redirect
// flows that the static HTTP form submitter cannot handle. It navigates to the
// login page in a real (headless) browser, fills the detected credential
// fields, submits, waits for the page to settle and captures the resulting
// session (cookies, plus an optional token from the body or localStorage).
//
// It intentionally drives go-rod directly rather than nuclei's headless engine
// package: that package imports authprovider, and autologin is (transitively)
// imported by authprovider, so depending on it would create an import cycle.
func LoginHeadless(ctx context.Context, cfg Config) (*Session, error) {
	if strings.TrimSpace(cfg.LoginURL) == "" {
		return nil, errkit.New("auto-login(headless): login-url is required")
	}
	loginURL, err := url.Parse(cfg.LoginURL)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): invalid login-url")
	}

	var tokenRe *regexp.Regexp
	if cfg.TokenRegex != "" {
		if tokenRe, err = regexp.Compile(cfg.TokenRegex); err != nil {
			return nil, errkit.Wrap(err, "auto-login(headless): invalid token-regex")
		}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 45 * time.Second
	}
	settle := cfg.SettleTime
	if settle == 0 {
		settle = 5 * time.Second
	}

	browser, cleanup, err := launchBrowser(cfg)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): failed to launch browser")
	}
	defer cleanup()

	// Use an incognito context for a clean, isolated cookie jar per login.
	incognito, err := browser.Incognito()
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): failed to create incognito context")
	}

	page, err := incognito.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): failed to open page")
	}
	defer func() { _ = page.Close() }()
	page = page.Context(ctx).Timeout(timeout)

	// Apply UA / custom headers before navigating so the login request carries
	// the same identity as the scan.
	if cfg.UserAgent != "" {
		if uaErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: cfg.UserAgent}); uaErr != nil {
			return nil, errkit.Wrap(uaErr, "auto-login(headless): failed to set user-agent")
		}
	}
	if len(cfg.CustomHeaders) > 0 {
		pairs := make([]string, 0, len(cfg.CustomHeaders)*2)
		for k, v := range cfg.CustomHeaders {
			pairs = append(pairs, k, v)
		}
		if _, hErr := page.SetExtraHeaders(pairs); hErr != nil {
			return nil, errkit.Wrap(hErr, "auto-login(headless): failed to set custom headers")
		}
	}

	if err := page.Navigate(cfg.LoginURL); err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): failed to navigate to login page")
	}
	if err := page.WaitLoad(); err != nil {
		return nil, errkit.Wrap(err, "auto-login(headless): login page failed to load")
	}
	// Give client-side scripts a chance to render the form.
	_ = rod.Try(func() { page.Timeout(settle).MustWaitStable() })

	if len(cfg.Steps) > 0 {
		// Explicit multi-step flow (username-first / SSO / consent screens).
		if err := runLoginSteps(ctx, page, cfg, settle); err != nil {
			return nil, err
		}
	} else if err := autoFillAndSubmit(ctx, page, cfg, loginURL, settle); err != nil {
		return nil, err
	}

	// Wait for the post-submit navigation / SPA state to settle.
	_ = rod.Try(func() { page.Timeout(settle).MustWaitStable() })
	_ = page.WaitLoad()

	session := &Session{}
	if info, ierr := page.Info(); ierr == nil {
		session.FinalURL = info.URL
	}

	// Capture cookies and web storage from the browser for the login + final hosts.
	session.Cookies = capturePageCookies(page, cfg.LoginURL, session.FinalURL)
	session.CookieHeader = renderCookieHeader(session.Cookies)
	session.LocalStorage = readStorage(page, "localStorage")
	session.SessionStorage = readStorage(page, "sessionStorage")

	// Token extraction: search the rendered body and web storage.
	if tokenRe != nil {
		var haystack strings.Builder
		if html, herr := page.HTML(); herr == nil {
			haystack.WriteString(html)
		}
		for _, store := range []map[string]string{session.LocalStorage, session.SessionStorage} {
			for k, v := range store {
				haystack.WriteString("\n")
				haystack.WriteString(k)
				haystack.WriteString("=")
				haystack.WriteString(v)
			}
		}
		if m := tokenRe.FindStringSubmatch(haystack.String()); len(m) > 1 {
			session.Token = m[1]
		}
	}

	// Fallback: many SPAs keep their bearer token in web storage (e.g.
	// localStorage["token"]) rather than a cookie. When no explicit token-regex
	// matched, surface a JWT-shaped value from web storage as the session token
	// so HTTP scan requests carry an Authorization header without the user
	// having to specify a token-regex.
	if session.Token == "" {
		session.Token = detectStorageJWT(session.LocalStorage, session.SessionStorage)
	}

	// Success heuristic: being re-prompted (final page still presents a login
	// form) with no token means the login failed.
	if session.Token == "" {
		if html, herr := page.HTML(); herr == nil {
			var finalParsed *url.URL
			if session.FinalURL != "" {
				finalParsed, _ = url.Parse(session.FinalURL)
			}
			if _, derr := DetectLoginForm(html, finalParsed); derr == nil {
				return nil, errkit.Wrapf(ErrLoginFailed, "still presented a login form at %s", session.FinalURL)
			}
		}
	}
	if len(session.Cookies) == 0 && session.Token == "" {
		return nil, errkit.Wrapf(ErrLoginFailed, "no cookies or token captured at %s", session.FinalURL)
	}
	return session, nil
}

// jwtValueRe matches a JWT-shaped value (header.payload.signature in base64url).
// It is intentionally not anchored so it also matches tokens wrapped in quotes
// or embedded in a small JSON blob stored in web storage.
var jwtValueRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}`)

// detectStorageJWT returns the first JWT-shaped value found across the supplied
// web storage maps, or "" when none is present. Keys that conventionally hold an
// auth token are inspected first (and otherwise keys are visited in sorted order)
// so the result is deterministic across runs.
func detectStorageJWT(stores ...map[string]string) string {
	preferredKeys := []string{"token", "access_token", "accesstoken", "jwt", "auth_token", "authtoken", "id_token", "idtoken", "bearer"}
	for _, store := range stores {
		if len(store) == 0 {
			continue
		}
		for _, want := range preferredKeys {
			for k, v := range store {
				if strings.EqualFold(k, want) {
					if m := jwtValueRe.FindString(v); m != "" {
						return m
					}
				}
			}
		}
	}
	for _, store := range stores {
		if len(store) == 0 {
			continue
		}
		keys := make([]string, 0, len(store))
		for k := range store {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if m := jwtValueRe.FindString(store[k]); m != "" {
				return m
			}
		}
	}
	return ""
}

// launchBrowser launches (or connects to) a browser and returns it with a
// cleanup func. A system-installed Chrome is preferred when available to avoid
// triggering a managed-browser download.
func launchBrowser(cfg Config) (*rod.Browser, func(), error) {
	if cfg.CDPEndpoint != "" {
		b := rod.New().ControlURL(cfg.CDPEndpoint)
		if err := b.Connect(); err != nil {
			return nil, nil, err
		}
		return b, func() { _ = b.Close() }, nil
	}

	l := launcher.New().
		Set("disable-gpu").
		Set("disable-notifications").
		Set("ignore-certificate-errors").
		Set("ignore-ssl-errors").
		Set("incognito").
		Headless(!cfg.ShowBrowser).
		Leakless(false)
	if osutils.IsLinux() {
		l = l.NoSandbox(true)
	}
	if cfg.Proxy != "" {
		l = l.Proxy(cfg.Proxy)
	}
	if path, ok := launcher.LookPath(); ok {
		l = l.Bin(path)
	} else if cfg.UseInstalledChrome {
		return nil, nil, errkit.New("use-installed-chrome set but no chrome binary found")
	}

	controlURL, err := l.Launch()
	if err != nil {
		return nil, nil, err
	}
	b := rod.New().ControlURL(controlURL)
	if err := b.Connect(); err != nil {
		l.Kill()
		return nil, nil, err
	}
	return b, func() { _ = b.Close(); l.Kill() }, nil
}

// autoFillAndSubmit runs the default single-shot login: detect the password
// (and username) field, type the credentials and submit.
func autoFillAndSubmit(ctx context.Context, page *rod.Page, cfg Config, loginURL *url.URL, settle time.Duration) error {
	// SPA forms are frequently injected after an async tick, so the password
	// field may not exist immediately after the initial settle. Wait (bounded by
	// settle) for it to appear before detecting, rather than failing outright.
	_ = waitVisible(ctx, page, `input[type="password"]`, settle)

	// Prefer field names detected from the rendered DOM; fall back to type-based
	// selectors for SPA inputs that carry no name attribute.
	var detected *LoginForm
	if html, herr := page.HTML(); herr == nil {
		detected, _ = DetectLoginForm(html, loginURL)
	}

	passEl := locatePasswordField(page, cfg, detected)
	if passEl == nil {
		return errkit.Wrap(ErrNoLoginForm, "auto-login(headless): no password field found in rendered page")
	}
	if userEl := locateUsernameField(page, cfg, detected); userEl != nil && cfg.Username != "" {
		if err := typeInto(userEl, cfg.Username); err != nil {
			return errkit.Wrap(err, "auto-login(headless): failed to type username")
		}
	}
	if err := typeInto(passEl, cfg.Password); err != nil {
		return errkit.Wrap(err, "auto-login(headless): failed to type password")
	}
	// Let the framework register the typed input and validate the form (which
	// often gates the submit button) before attempting to submit.
	_ = rod.Try(func() { page.Timeout(settle).MustWaitStable() })
	return submitForm(page, passEl, settle)
}

// submitForm submits a login form. It prefers clicking a submit control, but
// frameworks frequently keep that control disabled until the form validates, so
// the click is bounded by interactable-wait: if the button never becomes
// interactable (or the click fails) it falls back to pressing Enter in the
// given field, which reliably triggers native/framework form submission.
func submitForm(page *rod.Page, fallbackField *rod.Element, settle time.Duration) error {
	clickTimeout := settle
	if clickTimeout <= 0 {
		clickTimeout = 5 * time.Second
	}
	if btn := findVisible(page, `button[type="submit"]`, `input[type="submit"]`, `button:not([type])`, `[role="button"]`); btn != nil {
		// Bound the interactable-wait so a permanently-disabled button can't hang
		// the whole login; on failure we fall through to Enter-to-submit.
		clickErr := rod.Try(func() {
			b := btn.Timeout(clickTimeout)
			b.MustWaitInteractable()
			_ = b.ScrollIntoView()
			b.MustClick()
		})
		if clickErr == nil {
			return nil
		}
		if fallbackField == nil {
			return errkit.Wrapf(ErrLoginFailed, "auto-login(headless): submit button never became interactable: %s", clickErr)
		}
		// fall through to Enter-to-submit
	}
	if fallbackField != nil {
		if err := fallbackField.Type(input.Enter); err != nil {
			return errkit.Wrap(err, "auto-login(headless): failed to submit form")
		}
		return nil
	}
	return errkit.Wrap(ErrLoginFailed, "auto-login(headless): no submit control found and no field to submit")
}

// runLoginSteps executes an explicit multi-step login flow.
func runLoginSteps(ctx context.Context, page *rod.Page, cfg Config, settle time.Duration) error {
	for i, step := range cfg.Steps {
		action := strings.ToLower(strings.TrimSpace(step.Action))
		switch action {
		case "navigate":
			if err := page.Navigate(step.Value); err != nil {
				return errkit.Wrapf(err, "login step %d (navigate): failed", i)
			}
			_ = page.WaitLoad()
		case "fill", "input", "type":
			el := findVisible(page, byName(step.Selector), step.Selector)
			if el == nil {
				return errkit.Newf("login step %d (fill): element not found: %s", i, step.Selector)
			}
			if err := typeInto(el, expandCredentials(step.Value, cfg)); err != nil {
				return errkit.Wrapf(err, "login step %d (fill): failed", i)
			}
		case "click":
			el := findVisible(page, step.Selector)
			if el == nil {
				return errkit.Newf("login step %d (click): element not found: %s", i, step.Selector)
			}
			_ = el.ScrollIntoView()
			if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
				return errkit.Wrapf(err, "login step %d (click): failed", i)
			}
		case "waitvisible":
			if err := waitVisible(ctx, page, step.Selector, settle); err != nil {
				return errkit.Wrapf(err, "login step %d (waitvisible)", i)
			}
		case "wait":
			d := settle
			if step.Value != "" {
				if pd, perr := time.ParseDuration(step.Value); perr == nil {
					d = pd
				}
			}
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			}
		case "press":
			key, kerr := keyFromName(step.Value)
			if kerr != nil {
				return errkit.Wrapf(kerr, "login step %d (press)", i)
			}
			if step.Selector != "" {
				el := findVisible(page, byName(step.Selector), step.Selector)
				if el == nil {
					return errkit.Newf("login step %d (press): element not found: %s", i, step.Selector)
				}
				if err := el.Type(key); err != nil {
					return errkit.Wrapf(err, "login step %d (press): failed", i)
				}
			} else if err := page.Keyboard.Type(key); err != nil {
				return errkit.Wrapf(err, "login step %d (press): failed", i)
			}
		case "submit":
			if err := submitForm(page, findVisible(page, `input[type="password"]`), settle); err != nil {
				return errkit.Wrapf(err, "login step %d (submit)", i)
			}
		default:
			return errkit.Newf("login step %d: unknown action %q", i, step.Action)
		}
		// Let the page settle between steps so the next selector is present.
		_ = rod.Try(func() { page.Timeout(settle).MustWaitStable() })
	}
	return nil
}

// expandCredentials substitutes the {{username}}/{{password}} placeholders in a
// step value with the configured credentials.
func expandCredentials(value string, cfg Config) string {
	value = strings.ReplaceAll(value, "{{username}}", cfg.Username)
	value = strings.ReplaceAll(value, "{{password}}", cfg.Password)
	return value
}

// keyFromName maps a friendly key name to a go-rod input key.
func keyFromName(name string) (input.Key, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "enter", "return":
		return input.Enter, nil
	case "tab":
		return input.Tab, nil
	case "escape", "esc":
		return input.Escape, nil
	case "space":
		return input.Space, nil
	default:
		return 0, errkit.Newf("unsupported key %q (supported: enter, tab, escape, space)", name)
	}
}

// waitVisible polls until the selector becomes visible or the timeout elapses.
func waitVisible(ctx context.Context, page *rod.Page, selector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if findVisible(page, selector) != nil {
			return nil
		}
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errkit.Newf("timeout waiting for element to become visible: %s", selector)
}

// locatePasswordField finds the password input, honoring an explicit override
// (treated as a field name first, then as a raw CSS selector), then the
// detected name, then a generic selector.
func locatePasswordField(page *rod.Page, cfg Config, detected *LoginForm) *rod.Element {
	if cfg.PasswordField != "" {
		if el := findVisible(page, byName(cfg.PasswordField), cfg.PasswordField); el != nil {
			return el
		}
	}
	if detected != nil && detected.PasswordField != "" {
		if el := findVisible(page, byName(detected.PasswordField)); el != nil {
			return el
		}
	}
	return findVisible(page, `input[type="password"]`)
}

// locateUsernameField finds the username/identifier input using the same
// override/detected/heuristic precedence as the password field.
func locateUsernameField(page *rod.Page, cfg Config, detected *LoginForm) *rod.Element {
	if cfg.UsernameField != "" {
		if el := findVisible(page, byName(cfg.UsernameField), cfg.UsernameField); el != nil {
			return el
		}
	}
	if detected != nil && detected.UsernameField != "" {
		if el := findVisible(page, byName(detected.UsernameField)); el != nil {
			return el
		}
	}
	return findVisible(page,
		`input[type="email"]`,
		`input[autocomplete="username"]`,
		`input[name*="user" i]`,
		`input[name*="email" i]`,
		`input[name*="login" i]`,
		`input[type="text"]`,
	)
}

// byName builds a CSS attribute selector matching an input by its name.
func byName(name string) string {
	return fmt.Sprintf(`input[name=%q]`, name)
}

// findVisible returns the first visible element matching any of the selectors
// in priority order, or nil if none match.
func findVisible(page *rod.Page, selectors ...string) *rod.Element {
	for _, sel := range selectors {
		els, err := queryElements(page, sel)
		if err != nil {
			continue
		}
		for _, el := range els {
			if vis, verr := el.Visible(); verr == nil && vis {
				return el
			}
		}
	}
	return nil
}

// queryElements resolves a selector that may be CSS (default) or XPath. XPath
// selectors are prefixed with "xpath=" (emitted by the recording importer) or
// written as a raw "//"/"(//" expression. This lets recorded login flows, whose
// most stable selector is often an XPath, replay reliably.
func queryElements(page *rod.Page, sel string) (rod.Elements, error) {
	switch {
	case strings.HasPrefix(sel, "xpath="):
		return page.ElementsX(strings.TrimPrefix(sel, "xpath="))
	case strings.HasPrefix(sel, "//"), strings.HasPrefix(sel, "(//"):
		return page.ElementsX(sel)
	default:
		return page.Elements(sel)
	}
}

// typeInto focuses the element, clears any existing value and types the text so
// that JS frameworks observing input events (e.g. React controlled inputs) pick
// up the change.
func typeInto(el *rod.Element, text string) error {
	_ = el.ScrollIntoView()
	if err := el.Focus(); err != nil {
		return err
	}
	// Clear any pre-filled value by selecting all then overwriting.
	_ = el.SelectAllText()
	return el.Input(text)
}

// capturePageCookies pulls cookies the browser holds for the given URLs and
// converts them to net/http cookies, de-duplicated by name.
func capturePageCookies(page *rod.Page, urls ...string) []*http.Cookie {
	filtered := urls[:0]
	for _, u := range urls {
		if u != "" {
			filtered = append(filtered, u)
		}
	}
	cookies, err := page.Cookies(filtered)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []*http.Cookie
	for _, c := range cookies {
		if c == nil || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, HttpOnly: c.HTTPOnly, Secure: c.Secure})
	}
	return out
}

// readStorage returns the given web storage area (localStorage/sessionStorage)
// as a map, or nil on failure.
func readStorage(page *rod.Page, area string) map[string]string {
	obj, err := page.Eval(fmt.Sprintf(`() => JSON.stringify(window.%s)`, area))
	if err != nil || obj == nil {
		return nil
	}
	raw := obj.Value.Str()
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
