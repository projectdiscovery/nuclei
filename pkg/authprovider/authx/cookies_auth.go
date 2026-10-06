package authx

import (
	"net/http"
	"slices"

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
	var names []string
	for _, cookie := range s.Data.Cookies {
		c := &http.Cookie{
			Name:  cookie.Key,
			Value: cookie.Value,
		}
		req.AddCookie(c)
		names = append(names, cookie.Key)
	}
	markCookieAuth(req, names)
}

// ApplyOnRR applies the cookies auth strategy to the retryable request
func (s *CookiesAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	existingCookies := req.Cookies()

	for _, newCookie := range s.Data.Cookies {
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
	// Add new cookies
	var names []string
	for _, cookie := range s.Data.Cookies {
		req.AddCookie(&http.Cookie{
			Name:  cookie.Key,
			Value: cookie.Value,
		})
		names = append(names, cookie.Key)
	}
	markCookieAuth(req.Request, names)
}
