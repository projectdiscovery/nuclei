package code

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Request contains a code request to execute via nebula
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`

	ID string `yaml:"id"`

	// Name contains the identifier of the request
	Code string `yaml:"code"`

	CompiledOperators *operators.Operators
	options           *protocols.ExecuterOptions
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return 1
}
