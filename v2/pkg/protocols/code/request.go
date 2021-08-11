package code

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nebula"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	metadata["input"] = input

	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Str("input", input).Msgf("[%s] Code request for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", r.Code)
	}

	res, err := nebula.Eval(r.Code, metadata)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "code", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
	}
	if res == nil {
		return errors.Wrap(err, "could not execute code request")
	}
	r.options.Progress.IncrementRequests()

	r.options.Output.Request(r.options.TemplateID, input, "code", err)
	gologger.Verbose().Msgf("[%s] Executed code request for %s", r.options.TemplateID, input)

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped code response for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%+v", res)
	}
	outputEvent := r.responseToDSLMap(metadata, input, input)
	for k, v := range previous {
		outputEvent[k] = v
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)
	return nil
}
