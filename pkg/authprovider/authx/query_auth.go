package authx

import (
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
func (s *QueryAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)
	q := urlutil.NewOrderedParams()
	q.Decode(req.URL.RawQuery)

	for _, p := range s.Data.Params {
		if q.Get(p.Key) == "" || s.Data.Overwrite {
			q.Add(p.Key, p.Value)
		}
	}

	req.URL.RawQuery = q.Encode()
}
