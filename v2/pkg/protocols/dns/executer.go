package dns

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Executer executes a group of requests for a protocol
type Executer struct {
	requests []*Request
	options  *protocols.ExecuterOptions
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []*Request, options *protocols.ExecuterOptions) *Executer {
	return &Executer{requests: requests, options: options}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	for _, request := range e.requests {
		err := request.Compile(e.options)
		if err != nil {
			return err
		}
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input string) (bool, error) {
	var results bool

	for _, req := range e.requests {
		_ = req.ExecuteWithResults(input, nil, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult == nil {
				return
			}
			for _, result := range req.makeResultEvent(event) {
				results = true
				e.options.Output.Write(result)
			}
		})
	}
	return results, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input string, callback protocols.OutputEventCallback) error {
	for _, req := range e.requests {
		_ = req.ExecuteWithResults(input, nil, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult == nil {
				return
			}
			event.Results = req.makeResultEvent(event)
			callback(event)
		})
	}
	return nil
}
