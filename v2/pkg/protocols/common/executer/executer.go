package executer

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Executer executes a group of requests for a protocol
type Executer struct {
	requests []protocols.Request
	options  *protocols.ExecutorOptions
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []protocols.Request, options *protocols.ExecutorOptions) *Executer {
	return &Executer{requests: requests, options: options}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	cliOptions := e.options.Options

	for _, request := range e.requests {
		if err := request.Compile(e.options); err != nil {
			var dslCompilationError *dsl.CompilationError
			if errors.As(err, &dslCompilationError) {
				if cliOptions.Verbose {
					rawErrorMessage := dslCompilationError.Error()
					formattedErrorMessage := strings.ToUpper(rawErrorMessage[:1]) + rawErrorMessage[1:] + "."
					gologger.Warning().Msgf(formattedErrorMessage)
					gologger.Info().Msgf("The available custom DSL functions are:")
					fmt.Println(dsl.GetPrintableDslFunctionSignatures(cliOptions.NoColor))
				}
			}
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
func (e *Executer) Execute(input *contextargs.Context) (bool, error) {
	results := &atomic.Bool{}

	var lastMatcherEvent *output.InternalWrappedEvent
	writeFailureCallback := func(event *output.InternalWrappedEvent, matcherStatus bool) {
		if !results.Load() && matcherStatus {
			if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
				gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
			}
			results.CompareAndSwap(false, true)
		}
	}

	cliExecutorCallback := func(event *output.InternalWrappedEvent) {
		// If no results were found, and also interactsh is not being used
		// in that case we can skip it, otherwise we've to show failure in
		// case of matcher-status flag.
		if !event.HasOperatorResult() && !event.UsesInteractsh {
			lastMatcherEvent = event
		} else {
			if writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient) {
				results.CompareAndSwap(false, true)
			} else {
				lastMatcherEvent = event
			}
		}
	}
	if e.options.Flow != "" {
		return e.executeFlow(input, cliExecutorCallback)
	}
	_, err := e.executeWithCallback(input, results, cliExecutorCallback)
	if lastMatcherEvent != nil {
		writeFailureCallback(lastMatcherEvent, e.options.Options.MatcherStatus)
	}
	return results.Load(), err
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input *contextargs.Context, callback protocols.OutputEventCallback) error {
	gologger.Info().Msgf("[%s] Running on %s\n", e.options.TemplateID, input.MetaInput.PrettyPrint())
	userCallback := func(event *output.InternalWrappedEvent) {
		if event != nil {
			callback(event)
		}
	}
	var err error
	if e.options.Flow != "" {
		_, err = e.executeFlow(input, userCallback)
	} else {
		_, err = e.executeWithCallback(input, nil, userCallback)
	}
	return err
}

// executeWithCallback executes the protocol requests and calls the callback for each result.
func (e *Executer) executeWithCallback(input *contextargs.Context, results *atomic.Bool, callback protocols.OutputEventCallback) (bool, error) {
	if results == nil {
		results = &atomic.Bool{}
	}
	dynamicValues := make(map[string]interface{})
	if input.HasArgs() {
		input.ForEach(func(key string, value interface{}) {
			dynamicValues[key] = value
		})
	}
	previous := make(map[string]interface{})

	for _, req := range e.requests {
		inputItem := input.Clone()
		if e.options.InputHelper != nil && input.MetaInput.Input != "" {
			if inputItem.MetaInput.Input = e.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
				return false, nil
			}
		}

		err := req.ExecuteWithResults(inputItem, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			if event == nil {
				// ideally this should never happen since protocol exits on error and callback is not called
				return
			}
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
			if event.HasOperatorResult() {
				results.CompareAndSwap(false, true)
			}
			// for ExecuteWithResults : this callback will execute user defined callback and some error handling
			// for Execute : this callback will print the result to output
			callback(event)
		})
		if err != nil {
			if e.options.HostErrorsCache != nil {
				e.options.HostErrorsCache.MarkFailed(input.MetaInput.ID(), err)
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", e.options.TemplateID, input.MetaInput.PrettyPrint(), err)
		}
		// If a match was found and stop at first match is set, break out of the loop and return
		if results.Load() && (e.options.StopAtFirstMatch || e.options.Options.StopAtFirstMatch) {
			break
		}
	}
	return results.Load(), nil
}

// ExecuteFlow executes template as specified in js flow
// it is mutually exclusive with executeWithCallback
func (e *Executer) executeFlow(input *contextargs.Context, callback protocols.OutputEventCallback) (bool, error) {
	allprotos := make(map[string][]protocols.Request)
	for _, req := range e.requests {
		if req.Type() == types.MultiProtocol {
			// multiprotocol execution is also mutually exclusive with flow and is slightly advanced version of executeWithCallbac()
			// if request type is multiprotocol , then array does not contain any other request type
			gologger.Info().Msgf("reqtype is %v", req.Type().String())
			return e.executeWithCallback(input, nil, nil)
		}
		switch req.Type() {
		case types.DNSProtocol:
			allprotos[types.DNSProtocol.String()] = append(allprotos[types.DNSProtocol.String()], req)
		case types.HTTPProtocol:
			allprotos[types.HTTPProtocol.String()] = append(allprotos[types.HTTPProtocol.String()], req)
		case types.NetworkProtocol:
			allprotos[types.NetworkProtocol.String()] = append(allprotos[types.NetworkProtocol.String()], req)
		case types.FileProtocol:
			allprotos[types.FileProtocol.String()] = append(allprotos[types.FileProtocol.String()], req)
		case types.HeadlessProtocol:
			allprotos[types.HeadlessProtocol.String()] = append(allprotos[types.HeadlessProtocol.String()], req)
		case types.SSLProtocol:
			allprotos[types.SSLProtocol.String()] = append(allprotos[types.SSLProtocol.String()], req)
		case types.WebsocketProtocol:
			allprotos[types.WebsocketProtocol.String()] = append(allprotos[types.WebsocketProtocol.String()], req)
		case types.WHOISProtocol:
			allprotos[types.WHOISProtocol.String()] = append(allprotos[types.WHOISProtocol.String()], req)
		case types.CodeProtocol:
			allprotos[types.CodeProtocol.String()] = append(allprotos[types.CodeProtocol.String()], req)
		}
	}
	flow := &FlowExecutor{
		allProtocols: allprotos,
		input:        input,
		options:      e.options,
		allErrs: mapsutil.SyncLockMap[string, error]{
			ReadOnly: atomic.Bool{},
			Map:      make(map[string]error),
		},
		results: &atomic.Bool{},
	}

	if err := flow.Compile(callback); err != nil {
		return false, errorutil.NewWithErr(err).Msgf("could not compile flow")
	}

	return flow.Execute()
}
