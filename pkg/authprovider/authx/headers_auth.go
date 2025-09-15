package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy = &HeadersAuthStrategy{}
)

// HeadersAuthStrategy is a strategy for headers auth
type HeadersAuthStrategy struct {
	Data *Secret
}

// NewHeadersAuthStrategy creates a new headers auth strategy
func NewHeadersAuthStrategy(data *Secret) *HeadersAuthStrategy {
	return &HeadersAuthStrategy{Data: data}
}

// Apply applies the headers auth strategy to the request
// NOTE: This preserves exact header casing (e.g., barAuthToken stays as barAuthToken)
// This is useful for APIs that require case-sensitive header names
func (s *HeadersAuthStrategy) Apply(req *http.Request) {
	for _, header := range s.Data.Headers {
		req.Header[header.Key] = []string{header.Value}
	}
}

// ApplyOnRR applies the headers auth strategy to the retryable request
// NOTE: This preserves exact header casing (e.g., barAuthToken stays as barAuthToken)
// This is useful for APIs that require case-sensitive header names
func (s *HeadersAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	for _, header := range s.Data.Headers {
		req.Header[header.Key] = []string{header.Value}
	}
}
