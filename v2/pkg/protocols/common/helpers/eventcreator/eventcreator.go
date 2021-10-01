package eventcreator

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

func CreateEvent(request protocols.Request, outputEvent output.InternalEvent) *output.InternalWrappedEvent {
	return CreateEventWithAdditionalOptions(request, outputEvent, func(internalWrappedEvent *output.InternalWrappedEvent) {})
}

func CreateEventWithAdditionalOptions(request protocols.Request, outputEvent output.InternalEvent, addAdditionalOptions func(internalWrappedEvent *output.InternalWrappedEvent)) *output.InternalWrappedEvent {
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	for _, compiledOperator := range request.GetCompiledOperators() {
		if compiledOperator != nil {
			result, ok := compiledOperator.Execute(outputEvent, request.Match, request.Extract)
			if ok && result != nil {
				event.OperatorsResult = result
				addAdditionalOptions(event)
				event.Results = request.MakeResultEvent(event)
			}
		}
	}

	return event
}
