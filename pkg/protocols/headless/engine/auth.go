package engine

import (
	"net/http"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
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
