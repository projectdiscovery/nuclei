package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy = &BasicAuthStrategy{}
)

// BasicAuthStrategy is a strategy for basic auth
type BasicAuthStrategy struct {
	data *Secret
}

// NewBasicAuthStrategy creates a new basic auth strategy
func NewBasicAuthStrategy(data *Secret) *BasicAuthStrategy {
	return &BasicAuthStrategy{data: data}
}

// Apply applies the basic auth strategy to the request
func (s *BasicAuthStrategy) Apply(req *http.Request) {
	req.SetBasicAuth(s.data.Username, s.data.Password)
}

// ApplyOnRR applies the basic auth strategy to the retryable request
func (s *BasicAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	req.SetBasicAuth(s.data.Username, s.data.Password)
}
