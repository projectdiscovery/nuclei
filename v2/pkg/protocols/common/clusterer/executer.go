package clusterer

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// Executer executes a group of requests for a protocol for a clustered
// request. It is different from normal executers since the original
// operators are all combined and post processed after making the request.
//
// TODO: We only cluster http requests as of now.
type Executer struct {
	requests  *http.Request
	operators []*clusteredOperator
	options   *protocols.ExecuterOptions
}

type clusteredOperator struct {
	templateID   string
	templatePath string
	templateInfo model.Info
	operator     *operators.Operators
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []*templates.Template, options *protocols.ExecuterOptions) *Executer {
	executer := &Executer{
		options:  options,
		requests: requests[0].RequestsHTTP[0],
	}
	for _, req := range requests {
		executer.operators = append(executer.operators, &clusteredOperator{
			templateID:   req.ID,
			templateInfo: req.Info,
			templatePath: req.Path,
			operator:     req.RequestsHTTP[0].CompiledOperators,
		})
	}
	return executer
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	return e.requests.Compile(e.options)
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	count += e.requests.Requests()
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input string) (bool, error) {
	var results bool

	previous := make(map[string]interface{})
	dynamicValues := make(map[string]interface{})
	err := e.requests.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
		for _, operator := range e.operators {
			result, matched := operator.operator.Execute(event.InternalEvent, e.requests.Match, e.requests.Extract, e.options.Options.Debug || e.options.Options.DebugResponse)
			if matched && result != nil {
				event.OperatorsResult = result
				event.InternalEvent["template-id"] = operator.templateID
				event.InternalEvent["template-path"] = operator.templatePath
				event.InternalEvent["template-info"] = operator.templateInfo
				event.Results = e.requests.MakeResultEvent(event)
				results = true
				for _, r := range event.Results {
					if e.options.IssuesClient != nil {
						if err := e.options.IssuesClient.CreateIssue(r); err != nil {
							gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
						}
					}
					_ = e.options.Output.Write(r)
					e.options.Progress.IncrementMatched()
				}
			}
		}
	})
	if err != nil && e.options.HostErrorsCache != nil && e.options.HostErrorsCache.CheckError(err) {
		e.options.HostErrorsCache.MarkFailed(input)
	}
	return results, err
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input string, callback protocols.OutputEventCallback) error {
	dynamicValues := make(map[string]interface{})
	err := e.requests.ExecuteWithResults(input, dynamicValues, nil, func(event *output.InternalWrappedEvent) {
		for _, operator := range e.operators {
			result, matched := operator.operator.Execute(event.InternalEvent, e.requests.Match, e.requests.Extract, e.options.Options.Debug || e.options.Options.DebugResponse)
			if matched && result != nil {
				event.OperatorsResult = result
				event.InternalEvent["template-id"] = operator.templateID
				event.InternalEvent["template-path"] = operator.templatePath
				event.InternalEvent["template-info"] = operator.templateInfo
				event.Results = e.requests.MakeResultEvent(event)
				callback(event)
			}
		}
	})
	if err != nil && e.options.HostErrorsCache != nil && e.options.HostErrorsCache.CheckError(err) {
		e.options.HostErrorsCache.MarkFailed(input)
	}
	return err
}
