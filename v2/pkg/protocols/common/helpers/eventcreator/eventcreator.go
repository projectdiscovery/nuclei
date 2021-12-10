package eventcreator

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// CreateEvent wraps the outputEvent with the result of the operators defined on the request
func CreateEvent(request protocols.Request, outputEvent output.InternalEvent, debugEvent output.DebugEvent, isResponseDebug bool) *output.InternalWrappedEvent {
	return CreateEventWithAdditionalOptions(request, outputEvent, debugEvent, isResponseDebug, func(internalWrappedEvent *output.InternalWrappedEvent) {})
}

// CreateEventWithAdditionalOptions wraps the outputEvent with the result of the operators defined on the request and enables extending the resulting event with additional attributes or values.
func CreateEventWithAdditionalOptions(request protocols.Request, outputEvent output.InternalEvent, debugEvent output.DebugEvent, isResponseDebug bool,
	addAdditionalOptions func(internalWrappedEvent *output.InternalWrappedEvent)) *output.InternalWrappedEvent {
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent, Debug: &debugEvent}
	for _, compiledOperator := range request.GetCompiledOperators() {
		if compiledOperator != nil {
			result, ok := compiledOperator.Execute(outputEvent, request.Match, request.Extract, isResponseDebug)
			if ok && result != nil {
				event.OperatorsResult = result
				addAdditionalOptions(event)
				event.Results = append(event.Results, request.MakeResultEvent(event)...)
			}
		}
	}
	return event
}
