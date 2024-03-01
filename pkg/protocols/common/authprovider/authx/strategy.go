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
