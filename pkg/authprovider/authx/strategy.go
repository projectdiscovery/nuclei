package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

// AuthStrategy is an interface for auth strategies
// basic auth , bearer token, headers, cookies, query
type AuthStrategy interface {
	// Apply applies the strategy to the request
	Apply(*http.Request)
	// ApplyOnRR applies the strategy to the retryable request
	ApplyOnRR(*retryablehttp.Request)
}

// ResponseInspector is an optional interface that an AuthStrategy may implement
// to observe responses to authenticated requests. It is used to detect session
// expiry (e.g. a 401 after a previously valid session) and trigger
// re-authentication for subsequent requests.
type ResponseInspector interface {
	// OnResponse is called with the status code of a response to a request the
	// strategy authenticated. It returns true if re-authentication was triggered.
	OnResponse(statusCode int) bool
}

var (
	_ AuthStrategy           = &DynamicAuthStrategy{}
	_ ResponseInspector      = &DynamicAuthStrategy{}
	_ BrowserStorageProvider = &DynamicAuthStrategy{}
)

// DynamicAuthStrategy is an auth strategy for dynamic secrets
// it implements the AuthStrategy interface
type DynamicAuthStrategy struct {
	// Dynamic is the dynamic secret to use
	Dynamic Dynamic
}

// Apply applies the strategy to the request
func (d *DynamicAuthStrategy) Apply(req *http.Request) {
	d.Dynamic.ApplyStrategies(func(s AuthStrategy) {
		s.Apply(req)
	})
}

// ApplyOnRR applies the strategy to the retryable request
func (d *DynamicAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	d.Dynamic.ApplyStrategies(func(s AuthStrategy) {
		s.ApplyOnRR(req)
	})
}

// OnResponse inspects a response status code and marks the dynamic session for
// re-authentication when the code signals an expired session.
func (d *DynamicAuthStrategy) OnResponse(statusCode int) bool {
	return d.Dynamic.NotifyResponse(statusCode)
}

// WebStorage exposes the browser web storage captured by a headless auto-login
// so the headless engine can replay it into scan pages.
func (d *DynamicAuthStrategy) WebStorage() (map[string]string, map[string]string) {
	return d.Dynamic.WebStorage()
}
