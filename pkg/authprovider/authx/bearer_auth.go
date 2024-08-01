package authx

import "strings"

var (
	_ AuthStrategy = &BearerTokenAuthStrategy{}
)

// BearerTokenAuthStrategy is a strategy for bearer token auth
type BearerTokenAuthStrategy struct {
	Data *Secret
}

// NewBearerTokenAuthStrategy creates a new bearer token auth strategy
func NewBearerTokenAuthStrategy(data *Secret) *BearerTokenAuthStrategy {
	return &BearerTokenAuthStrategy{Data: data}
}

// Apply applies the bearer token auth strategy to the request
func (s *BearerTokenAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)
	authHeader := req.Header.Get("Authorization")

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer") || s.Data.Overwrite {
		req.Header.Set("Authorization", "Bearer "+s.Data.Token)
	}
}
