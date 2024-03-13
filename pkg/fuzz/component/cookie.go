package component

import (
	"context"
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
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
	if len(req.Cookies()) == 0 {
		return false, nil
	}
	c.req = req
	c.value = NewValue("")

	parsedCookies := make(map[string]interface{})
	for _, cookie := range req.Cookies() {
		parsedCookies[cookie.Name] = cookie.Value
	}
	if len(parsedCookies) == 0 {
		return false, nil
	}
	c.value.SetParsed(parsedCookies, "")
	return true, nil
}

// Iterate iterates through the component
func (c *Cookie) Iterate(callback func(key string, value interface{}) error) error {
	for key, value := range c.value.Parsed() {
		// Skip ignored cookies
		if _, ok := defaultIgnoredCookieKeys[key]; ok {
			continue
		}
		if err := callback(key, value); err != nil {
			return err
		}
	}
	return nil
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

	cloned.Header.Del("Cookie")
	for key, value := range c.value.Parsed() {
		cookie := &http.Cookie{
			Name:  key,
			Value: value.(string), // Assume the value is always a string for cookies
		}
		cloned.AddCookie(cookie)
	}
	return cloned, nil
}

// A list of cookies that are essential to the request and
// must not be fuzzed.
var defaultIgnoredCookieKeys = map[string]struct{}{
	"awsELB":                     {},
	"AWSALB":                     {},
	"AWSALBCORS":                 {},
	"__utma":                     {},
	"__utmb":                     {},
	"__utmc":                     {},
	"__utmt":                     {},
	"__utmz":                     {},
	"_ga":                        {},
	"_gat":                       {},
	"_gid":                       {},
	"_gcl_au":                    {},
	"_fbp":                       {},
	"fr":                         {},
	"__hstc":                     {},
	"hubspotutk":                 {},
	"__hssc":                     {},
	"__hssrc":                    {},
	"mp_mixpanel__c":             {},
	"JSESSIONID":                 {},
	"NREUM":                      {},
	"_pk_id":                     {},
	"_pk_ref":                    {},
	"_pk_ses":                    {},
	"_pk_cvar":                   {},
	"_pk_hsr":                    {},
	"_hjIncludedInSample":        {},
	"__cfduid":                   {},
	"cf_use_ob":                  {},
	"cf_ob_info":                 {},
	"intercom-session":           {},
	"optimizelyEndUserId":        {},
	"optimizelySegments":         {},
	"optimizelyBuckets":          {},
	"optimizelyPendingLogEvents": {},
	"YSC":                        {},
	"VISITOR_INFO1_LIVE":         {},
	"PREF":                       {},
	"GPS":                        {},
}
