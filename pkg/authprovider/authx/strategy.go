package authx

// AuthStrategy is an interface for auth strategies
// basic auth , bearer token, headers, cookies, query
type AuthStrategy interface {
	// Apply applies the strategy to the request
	Apply(any)
}

// DynamicAuthStrategy is an auth strategy for dynamic secrets
// it implements the AuthStrategy interface
type DynamicAuthStrategy struct {
	// Dynamic is the dynamic secret to use
	Dynamic Dynamic
}

// Apply applies the strategy to the request
func (d *DynamicAuthStrategy) Apply(rt any) {
	req := unwrapRequest(rt)

	strategy := d.Dynamic.GetStrategy()
	if strategy != nil {
		strategy.Apply(req)
	}
}
