package headless

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
)

// Request contains a Headless protocol request to be made from a template
type Request struct {
	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" jsonschema:"title=id of the request,description=Optional ID of the headless request"`

	// description: |
	//   Steps is the list of actions to run for headless request
	Steps []*engine.Action `yaml:"steps,omitempty" jsonschema:"title=list of actions for headless request,description=List of actions to run for headless request"`

	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// cache any variables that may be needed for operation.
	options *protocols.ExecuterOptions
}

// Step is a headless protocol request step.
type Step struct {
	// Action is the headless action to execute for the script
	Action string `yaml:"action"`
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	r.options = options
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return 1
}
