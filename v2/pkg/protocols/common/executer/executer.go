package executer

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
)

// Executer executes a group of requests for a protocol
type Executer struct {
	requests []protocols.Request
	options  *protocols.ExecuterOptions
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []protocols.Request, options *protocols.ExecuterOptions) *Executer {
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
func (e *Executer) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input string, dynamicValues, previous output.InternalEvent) (bool, error) {
	var results bool

	for _, req := range e.requests {
		err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					previous[builder.String()] = v
					builder.Reset()
				}
			}
			// If no results were found, and also interactsh is not being used
			// in that case we can skip it, otherwise we've to show failure in
			// case of matcher-status flag.
			if event.OperatorsResult == nil && !event.UsesInteractsh {
				if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
					gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
				}
			} else {
				if writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient) {
					results = true
				}
			}
		})
		if err != nil {
			if e.options.HostErrorsCache != nil {
				if e.options.HostErrorsCache.CheckError(err) {
					e.options.HostErrorsCache.MarkFailed(input)
				}
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", e.options.TemplateID, input, err)
		}
	}
	return results, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	for _, req := range e.requests {
		req := req

		err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					previous[builder.String()] = v
					builder.Reset()
				}
			}
			if event.OperatorsResult == nil {
				return
			}
			callback(event)
		})
		if err != nil {
			if e.options.HostErrorsCache != nil {
				if e.options.HostErrorsCache.CheckError(err) {
					e.options.HostErrorsCache.MarkFailed(input)
				}
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", e.options.TemplateID, input, err)
		}
	}
	return nil
}
