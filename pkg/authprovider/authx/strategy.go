package authx

import (
	"context"
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
	// strategy authenticated. sessionGeneration identifies the session that was
	// applied to that request (0 when unknown). It returns true if
	// re-authentication was triggered.
	OnResponse(statusCode int, sessionGeneration uint64) bool
}

var (
	_ AuthStrategy           = &DynamicAuthStrategy{}
	_ ResponseInspector      = &DynamicAuthStrategy{}
	_ BrowserStorageProvider = &DynamicAuthStrategy{}
)

type authSessionGenerationKey struct{}

// WithSessionGeneration stores the dynamic-session generation on the request
// context so a later response can be correlated with the session that
// authenticated it.
func WithSessionGeneration(req *http.Request, generation uint64) *http.Request {
	if req == nil || generation == 0 {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), authSessionGenerationKey{}, generation))
}

// SessionGenerationFromRequest returns the session generation stamped onto req,
// or 0 when absent.
func SessionGenerationFromRequest(req *http.Request) uint64 {
	if req == nil {
		return 0
	}
	gen, _ := req.Context().Value(authSessionGenerationKey{}).(uint64)
	return gen
}

// DynamicAuthStrategy is an auth strategy for dynamic secrets
// it implements the AuthStrategy interface
type DynamicAuthStrategy struct {
	// Dynamic is the dynamic secret to use
	Dynamic Dynamic
}

// Apply applies the strategy to the request
func (d *DynamicAuthStrategy) Apply(req *http.Request) {
	gen := d.Dynamic.ApplyStrategies(func(s AuthStrategy) {
		s.Apply(req)
	})
	if req != nil && gen != 0 {
		*req = *WithSessionGeneration(req, gen)
	}
}

// ApplyOnRR applies the strategy to the retryable request
func (d *DynamicAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	if req == nil {
		return
	}
	gen := d.Dynamic.ApplyStrategies(func(s AuthStrategy) {
		s.ApplyOnRR(req)
	})
	if gen != 0 && req.Request != nil {
		req.Request = WithSessionGeneration(req.Request, gen)
	}
}

// OnResponse inspects a response status code and marks the dynamic session for
// re-authentication when the code signals an expired session for the given
// generation.
func (d *DynamicAuthStrategy) OnResponse(statusCode int, sessionGeneration uint64) bool {
	return d.Dynamic.NotifyResponse(statusCode, sessionGeneration)
}

// WebStorage exposes the browser web storage captured by a headless auto-login
// so the headless engine can replay it into scan pages.
func (d *DynamicAuthStrategy) WebStorage() (map[string]string, map[string]string) {
	return d.Dynamic.WebStorage()
}
