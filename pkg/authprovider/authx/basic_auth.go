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
	Data *Secret
}

// NewBasicAuthStrategy creates a new basic auth strategy
func NewBasicAuthStrategy(data *Secret) *BasicAuthStrategy {
	return &BasicAuthStrategy{Data: data}
}

// Apply applies the basic auth strategy to the request
func (s *BasicAuthStrategy) Apply(req *http.Request) {
	req.SetBasicAuth(s.Data.Username, s.Data.Password)
}

// ApplyOnRR applies the basic auth strategy to the retryable request
func (s *BasicAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	req.SetBasicAuth(s.Data.Username, s.Data.Password)
}
