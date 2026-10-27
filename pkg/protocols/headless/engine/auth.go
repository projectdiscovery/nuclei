package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
)

// prepareAuthForNavigation refreshes authentication material before a
// same-origin navigation and installs cookies using the browser's native domain
// semantics. Authentication headers are applied separately to each intercepted
// request and are never installed as page-global extra headers.
func (p *Page) prepareAuthForNavigation(target *urlutil.URL) {
	if p.options == nil || p.options.AuthProvider == nil || target == nil || target.URL == nil || !p.authOriginMatches(target.URL) {
		return
	}

	_, cookies, generation := resolveAuthMaterial(p.options.AuthProvider, target)
	p.setAuthSessionGeneration(generation)

	if len(cookies) == 0 {
		if p.takeAuthRefreshPending() {
			p.applyAuthWebStorage()
		}
		return
	}

	if p.page != nil {
		params := make([]*proto.NetworkCookieParam, 0, len(cookies))
		for _, cookie := range cookies {
			param := &proto.NetworkCookieParam{
				Name:   cookie.Name,
				Value:  cookie.Value,
				URL:    target.String(),
				Secure: cookie.Secure,
			}
			if cookie.Domain != "" {
				param.Domain = cookie.Domain
			}
			if cookie.Path != "" {
				param.Path = cookie.Path
			}
			params = append(params, param)
		}
		if err := p.page.SetCookies(params); err != nil {
			gologger.Warning().Msgf("headless: could not set auth cookies for %s: %s", target.String(), err)
		}
	}
	if !p.options.DisableCookie && p.ctx != nil && p.ctx.CookieJar != nil {
		p.ctx.CookieJar.SetCookies(target.URL, cookies)
	}
	if p.takeAuthRefreshPending() {
		p.applyAuthWebStorage()
	}
}

// applyAuthHeaders resolves and applies authentication headers to one request.
// The explicit origin check is intentionally stricter than provider domain
// matching: credentials selected for the page's target origin must never follow
// a cross-origin subresource or navigation.
func (p *Page) applyAuthHeaders(req *http.Request) []string {
	if req == nil || req.URL == nil {
		return nil
	}
	headers := p.authHeaders(req.URL)
	for i := 0; i+1 < len(headers); i += 2 {
		if i == 0 || !strings.EqualFold(headers[i], headers[i-2]) {
			req.Header.Del(headers[i])
		}
		req.Header.Add(headers[i], headers[i+1])
	}
	return headers
}

func (p *Page) authHeaders(targetURL *url.URL) []string {
	if targetURL == nil || p.options == nil || p.options.AuthProvider == nil || !p.authOriginMatches(targetURL) {
		return nil
	}
	target, err := urlutil.Parse(targetURL.String())
	if err != nil {
		return nil
	}
	headers, _, generation := resolveAuthMaterial(p.options.AuthProvider, target)
	p.setAuthSessionGeneration(generation)
	return headers
}

func (p *Page) authOriginMatches(target *url.URL) bool {
	if p == nil || p.inputURL == nil || p.inputURL.URL == nil {
		return false
	}
	return sameOrigin(p.inputURL.URL, target)
}

func sameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func (p *Page) setAuthSessionGeneration(generation uint64) {
	p.authMutex.Lock()
	p.authSessionGeneration = generation
	p.authMutex.Unlock()
}

func (p *Page) currentAuthSessionGeneration() uint64 {
	p.authMutex.RLock()
	defer p.authMutex.RUnlock()
	return p.authSessionGeneration
}

func (p *Page) markAuthRefreshPending() {
	p.authMutex.Lock()
	p.authRefreshPending = true
	p.authMutex.Unlock()
}

func (p *Page) takeAuthRefreshPending() bool {
	p.authMutex.Lock()
	defer p.authMutex.Unlock()
	pending := p.authRefreshPending
	p.authRefreshPending = false
	return pending
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
			if inspector.OnResponse(statusCode, p.currentAuthSessionGeneration()) {
				p.markAuthRefreshPending()
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
func resolveAuthMaterial(provider authprovider.AuthProvider, target *urlutil.URL) (headers []string, cookies []*http.Cookie, generation uint64) {
	if provider == nil || target == nil {
		return nil, nil, 0
	}
	strategies := provider.LookupURLX(target)
	if len(strategies) == 0 {
		return nil, nil, 0
	}

	synthetic, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		gologger.Warning().Msgf("headless: could not build auth request for %s: %s", target.String(), err)
		return nil, nil, 0
	}
	for _, strategy := range strategies {
		if strategy != nil {
			strategy.Apply(synthetic)
		}
	}
	generation = authx.SessionGenerationFromRequest(synthetic)

	for key, values := range synthetic.Header {
		if strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, value := range values {
			headers = append(headers, key, value)
		}
	}
	return headers, synthetic.Cookies(), generation
}
