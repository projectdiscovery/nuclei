package authx

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy = &CookiesAuthStrategy{}
)

// CookiesAuthStrategy is a strategy for cookies auth
type CookiesAuthStrategy struct {
	Data *Secret
}

// NewCookiesAuthStrategy creates a new cookies auth strategy
func NewCookiesAuthStrategy(data *Secret) *CookiesAuthStrategy {
	return &CookiesAuthStrategy{Data: data}
}

// Apply applies the cookies auth strategy to the request
func (s *CookiesAuthStrategy) Apply(req *http.Request) {
	for _, cookie := range s.Data.Cookies {
		if !cookieAppliesToRequest(cookie, req.URL) {
			continue
		}
		c := &http.Cookie{
			Name:   cookie.Key,
			Value:  cookie.Value,
			Domain: cookie.Domain,
			Path:   cookie.Path,
			Secure: cookie.Secure,
		}
		req.AddCookie(c)
	}
}

// ApplyOnRR applies the cookies auth strategy to the retryable request
func (s *CookiesAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	existingCookies := req.Cookies()
	var reqURL *url.URL
	if req.URL != nil {
		reqURL = req.URL.URL
	}

	for _, newCookie := range s.Data.Cookies {
		if !cookieAppliesToRequest(newCookie, reqURL) {
			continue
		}
		for i, existing := range existingCookies {
			if existing.Name == newCookie.Key {
				existingCookies = slices.Delete(existingCookies, i, i+1)
				break
			}
		}
	}

	// Clear and reset remaining cookies
	req.Header.Del("Cookie")
	for _, cookie := range existingCookies {
		req.AddCookie(cookie)
	}
	// Add new cookies that match this request's scope
	for _, cookie := range s.Data.Cookies {
		if !cookieAppliesToRequest(cookie, reqURL) {
			continue
		}
		req.AddCookie(&http.Cookie{
			Name:   cookie.Key,
			Value:  cookie.Value,
			Domain: cookie.Domain,
			Path:   cookie.Path,
			Secure: cookie.Secure,
		})
	}
}

// cookieAppliesToRequest reports whether a captured/configured cookie should be
// attached to reqURL. Unscoped cookies (empty Domain) always apply, preserving
// backward compatibility for hand-written secrets.
func cookieAppliesToRequest(cookie Cookie, reqURL *url.URL) bool {
	if reqURL == nil {
		return cookie.Domain == ""
	}
	if cookie.Secure && !strings.EqualFold(reqURL.Scheme, "https") {
		return false
	}
	if cookie.Domain != "" && !cookieDomainMatchesHost(cookie.Domain, reqURL.Hostname()) {
		return false
	}
	path := cookie.Path
	if path == "" {
		path = "/"
	}
	reqPath := reqURL.EscapedPath()
	if reqPath == "" {
		reqPath = "/"
	}
	return cookiePathMatches(path, reqPath)
}

// cookieDomainMatchesHost implements a conservative Domain attribute match:
// exact host equality, or a leading-dot domain matching a subdomain suffix.
func cookieDomainMatchesHost(domain, host string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	host = strings.TrimSpace(strings.ToLower(host))
	if domain == "" || host == "" {
		return false
	}
	domain = strings.TrimPrefix(domain, ".")
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// cookiePathMatches implements the RFC 6265 path-match algorithm.
func cookiePathMatches(cookiePath, reqPath string) bool {
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	if len(reqPath) == len(cookiePath) || strings.HasSuffix(cookiePath, "/") {
		return true
	}
	return reqPath[len(cookiePath)] == '/'
}
