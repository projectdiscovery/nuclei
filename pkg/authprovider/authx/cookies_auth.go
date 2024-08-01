package authx

import "net/http"

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
func (s *CookiesAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)
	cookies := req.Cookies()

	for _, cookie := range s.Data.Cookies {
		exists := func() (bool, int) {
			// check for existing cookies
			for i, c := range cookies {
				if c.Name == cookie.Key {
					return true, i
				}
			}

			return false, -1
		}

		if _, pos := exists(); pos >= 0 {
			if !s.Data.Overwrite {
				continue
			}

			// rm existing cookie from `cookies`
			cookies = append(cookies[:pos], cookies[pos+1:]...)

			// rebuild cookie header
			req.Header.Del("Cookie")
			for _, c := range cookies {
				req.AddCookie(c)
			}
		}

		req.AddCookie(&http.Cookie{
			Name:  cookie.Key,
			Value: cookie.Value,
		})
	}
}
