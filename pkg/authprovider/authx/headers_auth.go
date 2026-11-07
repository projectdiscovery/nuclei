package authx

import (
	"net/http"
	"strings"

	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
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
		if strings.EqualFold(header.Key, "Cookie") {
			var names []string
			for _, part := range httputil.SplitCookieHeader(header.Value) {
				name, _, _ := strings.Cut(part, "=")
				names = append(names, strings.TrimSpace(name))
			}
			markCookieAuth(req, names)
		}
	}
}

// ApplyOnRR applies the headers auth strategy to the retryable request
// NOTE: This preserves exact header casing (e.g., barAuthToken stays as barAuthToken)
// This is useful for APIs that require case-sensitive header names
func (s *HeadersAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	s.Apply(req.Request)
}
