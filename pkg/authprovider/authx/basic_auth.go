package authx

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
func (s *BasicAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)
	if _, _, exists := req.BasicAuth(); !exists || s.Data.Overwrite {
		// NOTE(dwisiswant0): if the Basic auth is invalid, e.g. "Basic xyz",
		// `exists` will be `false`. I'm not sure if we should check it through
		// the presence of an "Authorization" header.
		req.SetBasicAuth(s.Data.Username, s.Data.Password)
	}
}
