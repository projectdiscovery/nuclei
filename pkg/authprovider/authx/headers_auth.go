package authx

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
func (s *HeadersAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)

	for _, header := range s.Data.Headers {
		if len(req.Header[header.Key]) < 1 || s.Data.Overwrite {
			req.Header[header.Key] = []string{header.Value}
		}
	}
}
