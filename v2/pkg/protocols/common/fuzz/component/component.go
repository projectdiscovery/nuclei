package component

import (
	"errors"

	"github.com/leslie-qiwa/flat"
	"github.com/projectdiscovery/retryablehttp-go"
)

// ErrSetValue is a error raised when a value cannot be set
var ErrSetValue = errors.New("could not set value")

// Component is a component for a request
type Component interface {
	// Name returns the name of the component
	Name() string
	// Parse parses the component and returns the
	// parsed component
	Parse(req *retryablehttp.Request) (bool, error)
	// Iterate iterates through the component
	//
	// We cannot iterate normally because there
	// can be multiple nesting. So we need to a do traversal
	// and get keys with values that can be assigned values dynamically.
	// Therefore we flatten the value map and iterate over it.
	//
	// The mutation layer decides how to change the value and then
	// the SetValue method is called to set the final string into
	// the Value. The value container handles arrays, maps, strings etc
	// and then encodes and converts them into final string.
	Iterate(func(key string, value interface{}))
	// SetValue sets a value in the component
	// for a key
	//
	// After calling setValue for mutation, the value must be
	// called again so as to reset the body to its original state.
	SetValue(key string, value string) error
	// Rebuild returns a new request with the
	// component rebuilt
	Rebuild() (*retryablehttp.Request, error)
}

const (
	// RequestBodyComponent is the name of the request body component
	RequestBodyComponent = "body"
	// RequestQueryComponent is the name of the request query component
	RequestQueryComponent = "query"
	// RequestURLComponent is the name of the request url component
	RequestURLComponent = "url"
	// RequestHeaderComponent is the name of the request header component
	RequestHeaderComponent = "header"
)

// Components is a list of all available components
var Components = []string{
	//RequestBodyComponent,
	//RequestQueryComponent,
	//RequestURLComponent,
	RequestHeaderComponent,
}

// New creates a new component for a componentType
func New(componentType string) Component {
	switch componentType {
	case "body":
		return NewBody()
	case "query":
		return NewQuery()
	case "url":
		return NewURL()
	case "header":
		return NewHeader()
	}
	return nil
}

var (
	flatOpts = &flat.Options{
		Safe:      true,
		Delimiter: "~",
	}
)
