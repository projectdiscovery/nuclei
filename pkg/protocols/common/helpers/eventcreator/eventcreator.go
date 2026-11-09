package eventcreator

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Record, when set, receives the event of every request before its operators
// run, which is what a replay needs to run them again. Every protocol builds
// its result here, so setting it covers all of them.
var Record func(request protocols.Request, event output.InternalEvent)

// CreateEvent wraps the outputEvent with the result of the operators defined on the request
func CreateEvent(request protocols.Request, outputEvent output.InternalEvent, isResponseDebug bool) *output.InternalWrappedEvent {
	return CreateEventWithAdditionalOptions(request, outputEvent, isResponseDebug, nil)
}

// CreateEventWithAdditionalOptions wraps the outputEvent with the result of the operators defined on the request
// and enables extending the resulting event with additional attributes or values.
func CreateEventWithAdditionalOptions(request protocols.Request, outputEvent output.InternalEvent, isResponseDebug bool,
	addAdditionalOptions func(internalWrappedEvent *output.InternalWrappedEvent)) *output.InternalWrappedEvent {
	if Record != nil {
		Record(request, outputEvent)
	}
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}

	// Dump response variables if ran in debug mode
	if vardump.EnableVarDump {
		protoName := cases.Title(language.English).String(request.Type().String())
		gologger.Debug().Msgf("%v Protocol response variables: %s\n", protoName, vardump.DumpVariables(outputEvent))
	}
	for _, compiledOperator := range request.GetCompiledOperators() {
		if compiledOperator != nil {
			result, ok := compiledOperator.Execute(outputEvent, request.Match, request.Extract, isResponseDebug)
			if ok && result != nil {
				// if result has both extracted values and dynamic values, put dynamic values in data
				// and remove dynamic values to avoid skipping legitimate event
				if (len(result.Extracts) > 0 || len(result.OutputExtracts) > 0) && len(result.DynamicValues) > 0 {
					for k, v := range result.DynamicValues {
						event.InternalEvent[k] = v
					}
					result.DynamicValues = nil
				}
				event.OperatorsResult = result
				if addAdditionalOptions != nil {
					addAdditionalOptions(event)
				}
				event.Results = append(event.Results, request.MakeResultEvent(event)...)
			}
		}
	}
	return event
}

func CreateEventWithOperatorResults(request protocols.Request, internalEvent output.InternalEvent, operatorResult *operators.Result) *output.InternalWrappedEvent {
	event := &output.InternalWrappedEvent{InternalEvent: internalEvent}
	event.OperatorsResult = operatorResult
	event.Results = append(event.Results, request.MakeResultEvent(event)...)
	return event
}
