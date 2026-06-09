package autologin

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/utils/errkit"
)

// CaptureOnce launches a visible browser at cfg.LoginURL and lets the user log
// in manually, then — once ready() returns — captures the resulting session
// (cookies, web storage and an optional token). It performs no automated form
// filling.
//
// This is the "log in yourself, I'll grab the session" mode for one-off
// authenticated scans of flows that are impractical to record/replay
// (hardware-key MFA, CAPTCHA, interactive SSO). Because the captured session is
// a point-in-time snapshot there is no automated re-authentication; ready
// blocks until the caller signals login completion (e.g. the user pressing
// Enter in the terminal).
func CaptureOnce(ctx context.Context, cfg Config, ready func() error) (*Session, error) {
	if ready == nil {
		return nil, errkit.New("auto-login(capture): a ready signal is required")
	}
	if strings.TrimSpace(cfg.LoginURL) == "" {
		return nil, errkit.New("auto-login(capture): login-url is required")
	}
	if _, err := url.Parse(cfg.LoginURL); err != nil {
		return nil, errkit.Wrap(err, "auto-login(capture): invalid login-url")
	}

	var tokenRe *regexp.Regexp
	if cfg.TokenRegex != "" {
		var err error
		if tokenRe, err = regexp.Compile(cfg.TokenRegex); err != nil {
			return nil, errkit.Wrap(err, "auto-login(capture): invalid token-regex")
		}
	}

	// Force a visible browser so the user can interact with the login page.
	cfg.ShowBrowser = true

	browser, cleanup, err := launchBrowser(cfg)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(capture): failed to launch browser")
	}
	defer cleanup()

	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login(capture): failed to open page")
	}
	defer func() { _ = page.Close() }()
	page = page.Context(ctx)

	if cfg.UserAgent != "" {
		if uaErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: cfg.UserAgent}); uaErr != nil {
			return nil, errkit.Wrap(uaErr, "auto-login(capture): failed to set user-agent")
		}
	}
	if len(cfg.CustomHeaders) > 0 {
		pairs := make([]string, 0, len(cfg.CustomHeaders)*2)
		for k, v := range cfg.CustomHeaders {
			pairs = append(pairs, k, v)
		}
		if _, hErr := page.SetExtraHeaders(pairs); hErr != nil {
			return nil, errkit.Wrap(hErr, "auto-login(capture): failed to set custom headers")
		}
	}

	if err := page.Navigate(cfg.LoginURL); err != nil {
		return nil, errkit.Wrap(err, "auto-login(capture): failed to navigate to login page")
	}
	_ = page.WaitLoad()

	// Block until the user signals that the manual login is complete.
	if err := ready(); err != nil {
		return nil, errkit.Wrap(err, "auto-login(capture): aborted before capture")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session := &Session{}
	if info, ierr := page.Info(); ierr == nil {
		session.FinalURL = info.URL
	}
	session.Cookies = capturePageCookies(page, cfg.LoginURL, session.FinalURL)
	session.CookieHeader = renderCookieHeader(session.Cookies)
	session.LocalStorage = readStorage(page, "localStorage")
	session.SessionStorage = readStorage(page, "sessionStorage")

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

	if len(session.Cookies) == 0 && session.Token == "" && len(session.LocalStorage) == 0 && len(session.SessionStorage) == 0 {
		return nil, errkit.New("auto-login(capture): no session captured (no cookies, token or web storage found)")
	}
	return session, nil
}
