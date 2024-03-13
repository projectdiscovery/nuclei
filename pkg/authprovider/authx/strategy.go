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

// DynamicAuthStrategy is an auth strategy for dynamic secrets
// it implements the AuthStrategy interface
type DynamicAuthStrategy struct {
	// Dynamic is the dynamic secret to use
	Dynamic Dynamic
}

// Apply applies the strategy to the request
func (d *DynamicAuthStrategy) Apply(req *http.Request) {
	strategy := d.Dynamic.GetStrategy()
	if strategy != nil {
		strategy.Apply(req)
	}
}

// ApplyOnRR applies the strategy to the retryable request
func (d *DynamicAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	strategy := d.Dynamic.GetStrategy()
	if strategy != nil {
		strategy.ApplyOnRR(req)
	}
}
