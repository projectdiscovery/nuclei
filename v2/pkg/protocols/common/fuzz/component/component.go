package component

import "github.com/projectdiscovery/retryablehttp-go"

// Component is a component for a request
type Component interface {
	// Name returns the name of the component
	Name() string
	// Parse parses the component and returns the
	// parsed component
	Parse(req *retryablehttp.Request) error
	// Iterate iterates through the component
	Iterate(func(key string, value interface{}))
	// SetValue sets a value in the component
	// for a key
	SetValue(key string, value string) error
	// Rebuild returns a new request with the
	// component rebuilt
	Rebuild() (*retryablehttp.Request, error)
}
