package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	_ AuthStrategy = &QueryAuthStrategy{}
)

// QueryAuthStrategy is a strategy for query auth
type QueryAuthStrategy struct {
	Data *Secret
}

// NewQueryAuthStrategy creates a new query auth strategy
func NewQueryAuthStrategy(data *Secret) *QueryAuthStrategy {
	return &QueryAuthStrategy{Data: data}
}

// Apply applies the query auth strategy to the request
func (s *QueryAuthStrategy) Apply(req *http.Request) {
	q := urlutil.NewOrderedParams()
	q.Decode(req.URL.RawQuery)
	for _, p := range s.Data.Params {
		q.Add(p.Key, p.Value)
	}
	req.URL.RawQuery = q.Encode()
}

// ApplyOnRR applies the query auth strategy to the retryable request
func (s *QueryAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	q := urlutil.NewOrderedParams()
	q.Decode(req.Request.URL.RawQuery)
	for _, p := range s.Data.Params {
		q.Add(p.Key, p.Value)
	}
	req.Request.URL.RawQuery = q.Encode()
}
