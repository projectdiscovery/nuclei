package component

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Cookie is a component for a request cookie
type Cookie struct {
	value *Value

	req *retryablehttp.Request
}

var _ Component = &Cookie{}

// NewCookie creates a new cookie component
func NewCookie() *Cookie {
	return &Cookie{}
}

// Name returns the name of the component
func (c *Cookie) Name() string {
	return RequestCookieComponent
}

// Parse parses the component and returns the
// parsed component
func (c *Cookie) Parse(req *retryablehttp.Request) (bool, error) {
	c.req = req
	c.value = NewValue("")

	parsedCookies := mapsutil.NewOrderedMap[string, any]()

	// First, read cookies from the CookieJar
	for _, cookie := range req.Cookies() {
		parsedCookies.Set(cookie.Name, cookie.Value)
	}

	// Also read cookies from the Cookie header (set via -H flag)
	// This ensures cookies specified via command line are preserved
	if cookieHeader := req.Header.Get("Cookie"); cookieHeader != "" {
		cookies := parseCookieHeader(cookieHeader)
		for name, value := range cookies {
			// Only add if not already present from CookieJar
			if !parsedCookies.Has(name) {
				parsedCookies.Set(name, value)
			}
		}
	}

	if parsedCookies.Len() == 0 {
		return false, nil
	}
	c.value.SetParsed(dataformat.KVOrderedMap(&parsedCookies), "")
	return true, nil
}

// parseCookieHeader parses a Cookie header value into a map
func parseCookieHeader(header string) map[string]string {
	cookies := make(map[string]string)
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx != -1 {
			name := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			if name != "" {
				cookies[name] = value
			}
		}
	}
	return cookies
}

// Iterate iterates through the component
func (c *Cookie) Iterate(callback func(key string, value interface{}) error) (err error) {
	c.value.parsed.Iterate(func(key string, value any) bool {
		if errx := callback(key, value); errx != nil {
			err = errx
			return false
		}
		return true
	})
	return
}

// SetValue sets a value in the component
// for a key
func (c *Cookie) SetValue(key string, value string) error {
	if !c.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Delete deletes a key from the component
func (c *Cookie) Delete(key string) error {
	if !c.value.Delete(key) {
		return ErrKeyNotFound
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (c *Cookie) Rebuild() (*retryablehttp.Request, error) {
	cloned := c.req.Clone(context.Background())

	// Clear existing cookies to prevent duplication with auth-file cookies
	// The cloned request may contain cookies from the original request
	// We need to remove them before adding our fuzzed cookies
	cloned.Header.Del("Cookie")
	// Note: CookieJar cookies are preserved in the clone
	// We rely on AddCookie to overwrite any existing cookies with the same name
	
	c.value.parsed.Iterate(func(key string, value any) bool {
		cookie := &http.Cookie{
			Name:  key,
			Value: fmt.Sprint(value), // Assume the value is always a string for cookies
		}
		cloned.AddCookie(cookie)
		return true
	})
	return cloned, nil
}

// Clone clones current state of this component
func (c *Cookie) Clone() Component {
	return &Cookie{
		value: c.value.Clone(),
		req:   c.req.Clone(context.Background()),
	}
}
