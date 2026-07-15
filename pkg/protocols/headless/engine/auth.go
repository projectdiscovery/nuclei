package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
)

// applyAuthStrategies injects credentials from the configured auth provider into
// the browser page, so authenticated headless scans work the same way the HTTP
// protocol does (which previously was the only protocol wired to the secrets
// file).
//
// It resolves the auth strategies for the page's input URL, materializes them
// onto a synthetic request (reusing the exact same Apply logic as the HTTP
// path), then pushes the resulting headers and cookies to the browser and seeds
// the shared cookie jar used by the hijack HTTP client.
//
// NOTE: extra headers set via CDP are sent on every request the page makes,
// including cross-origin subresources. Cookies remain domain-scoped by the
// browser. Query-parameter auth is not applied globally in headless mode.
func (p *Page) applyAuthStrategies() {
	if p.options == nil || p.options.AuthProvider == nil || p.inputURL == nil {
		return
	}

	headers, cookies := resolveAuthMaterial(p.options.AuthProvider, p.inputURL)
	if len(headers) == 0 && len(cookies) == 0 {
		return
	}

	if len(headers) > 0 {
		if _, err := p.page.SetExtraHeaders(headers); err != nil {
			gologger.Warning().Msgf("headless: could not set auth headers for %s: %s", p.inputURL.String(), err)
		}
	}

	if len(cookies) == 0 {
		return
	}
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, cookie := range cookies {
		params = append(params, &proto.NetworkCookieParam{
			Name:  cookie.Name,
			Value: cookie.Value,
			URL:   p.inputURL.String(),
		})
	}
	if err := p.page.SetCookies(params); err != nil {
		gologger.Warning().Msgf("headless: could not set auth cookies for %s: %s", p.inputURL.String(), err)
	}
	if !p.options.DisableCookie && p.ctx != nil && p.ctx.CookieJar != nil {
		if u := p.inputURL.URL; u != nil {
			p.ctx.CookieJar.SetCookies(u, cookies)
		}
	}
}

// notifyAuthResponse forwards the main navigation response status to any auth
// strategies that inspect responses (e.g. dynamic/auto-login secrets), so an
// expired session (a status listed in reauth-status-codes) is marked stale and
// re-authenticated before the next headless navigation. This mirrors the HTTP
// protocol's NotifyResponse behaviour.
func (p *Page) notifyAuthResponse(statusCode int) {
	if p.options == nil || p.options.AuthProvider == nil || p.inputURL == nil {
		return
	}
	for _, strategy := range p.options.AuthProvider.LookupURLX(p.inputURL) {
		if inspector, ok := strategy.(authx.ResponseInspector); ok {
			if inspector.OnResponse(statusCode) {
				gologger.Verbose().Msgf("[authprovider] Session expired (status %d) for %s, will re-authenticate", statusCode, p.inputURL.Host)
			}
		}
	}
}

// applyAuthWebStorage seeds browser web storage (localStorage/sessionStorage)
// captured by a headless auto-login into the page. Because web storage is
// origin-scoped and only exists once a document for the origin is loaded, it is
// injected via an on-new-document script (guarded by origin) that runs before
// page scripts on every navigation — so client-side code that reads its token
// from storage behaves as if logged in.
func (p *Page) applyAuthWebStorage() {
	if p.options == nil || p.options.AuthProvider == nil || p.inputURL == nil {
		return
	}
	local, session := resolveBrowserStorage(p.options.AuthProvider, p.inputURL)
	if len(local) == 0 && len(session) == 0 {
		return
	}
	origin := ""
	if u := p.inputURL.URL; u != nil {
		origin = u.Scheme + "://" + u.Host
	}
	js := buildStorageInjectorJS(origin, local, session)
	if js == "" {
		return
	}
	if _, err := p.page.EvalOnNewDocument(js); err != nil {
		gologger.Warning().Msgf("headless: could not seed web storage for %s: %s", p.inputURL.String(), err)
	}
}

// resolveBrowserStorage merges the web storage carried by any
// BrowserStorageProvider strategy resolved for the target URL.
func resolveBrowserStorage(provider authprovider.AuthProvider, target *urlutil.URL) (local map[string]string, session map[string]string) {
	if provider == nil || target == nil {
		return nil, nil
	}
	for _, strategy := range provider.LookupURLX(target) {
		sp, ok := strategy.(authx.BrowserStorageProvider)
		if !ok {
			continue
		}
		l, s := sp.WebStorage()
		for k, v := range l {
			if local == nil {
				local = map[string]string{}
			}
			local[k] = v
		}
		for k, v := range s {
			if session == nil {
				session = map[string]string{}
			}
			session[k] = v
		}
	}
	return local, session
}

// buildStorageInjectorJS builds an on-new-document script that, only when the
// document origin matches, seeds the given localStorage/sessionStorage items.
func buildStorageInjectorJS(origin string, local, session map[string]string) string {
	localJSON, err := json.Marshal(local)
	if err != nil {
		return ""
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return ""
	}
	originJSON, err := json.Marshal(origin)
	if err != nil {
		return ""
	}
	// EvalOnNewDocument evaluates the source directly (it is not invoked as a
	// function), so this must be a self-executing statement. It is defensive: it
	// no-ops on origin mismatch and swallows errors (e.g. storage disabled) so it
	// can never break the navigation.
	return fmt.Sprintf(`(function () {
  try {
    if (%s && window.location && window.location.origin !== %s) { return; }
    var l = %s, s = %s, k;
    for (k in l) { try { window.localStorage.setItem(k, l[k]); } catch (e) {} }
    for (k in s) { try { window.sessionStorage.setItem(k, s[k]); } catch (e) {} }
  } catch (e) {}
})();`, originJSON, originJSON, localJSON, sessionJSON)
}

// resolveAuthMaterial resolves the auth strategies for the given URL into a flat
// list of header key/value pairs (suitable for rod's SetExtraHeaders, excluding
// the Cookie header) and the cookies to set on the browser.
//
// It is kept free of any browser dependency so it can be unit-tested in
// isolation. The header/cookie values are produced by applying the strategies to
// a synthetic request, guaranteeing parity with the HTTP protocol's behaviour.
func resolveAuthMaterial(provider authprovider.AuthProvider, target *urlutil.URL) (headers []string, cookies []*http.Cookie) {
	if provider == nil || target == nil {
		return nil, nil
	}
	strategies := provider.LookupURLX(target)
	if len(strategies) == 0 {
		return nil, nil
	}

	synthetic, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		gologger.Warning().Msgf("headless: could not build auth request for %s: %s", target.String(), err)
		return nil, nil
	}
	for _, strategy := range strategies {
		if strategy != nil {
			strategy.Apply(synthetic)
		}
	}

	for key, values := range synthetic.Header {
		if strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, value := range values {
			headers = append(headers, key, value)
		}
	}
	return headers, synthetic.Cookies()
}
