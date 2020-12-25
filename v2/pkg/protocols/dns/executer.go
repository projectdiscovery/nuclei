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

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []*Request, options *protocols.ExecuterOptions) *Executer {
	return &Executer{requests: requests, options: options}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	for _, request := range e.requests {
		if err := request.Compile(e.options); err != nil {
			return err
		}
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int64 {
	var count int64
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input string) (bool, error) {
	var results bool

	for _, req := range e.requests {
		events, err := req.ExecuteWithResults(input)
		if err != nil {
			return false, err
		}

		// If we have a result field, we should add a result to slice.
		for _, event := range events {
			if event.OperatorsResult != nil {
				for _, result := range req.makeResultEvent(event) {
					results = true
					e.options.Output.Write(result)
				}
			}
		}
	}
	return results, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input string) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	for _, req := range e.requests {
		events, err := req.ExecuteWithResults(input)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			if event.OperatorsResult != nil {
				results = append(results, req.makeResultEvent(event)...)
			}
		}
	}
	return results, nil
}
