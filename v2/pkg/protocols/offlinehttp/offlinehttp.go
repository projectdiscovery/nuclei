package offlinehttp

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Request is a offline http response processing request
type Request struct {
	options           *protocols.ExecuterOptions
	compiledOperators []*operators.Operators
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return ""
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	for _, operator := range options.Operators {
		if err := operator.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.compiledOperators = append(request.compiledOperators, operator)
	}
	request.options = options
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 1
}
