package tmplexec

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v2/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v2/pkg/tmplexec/generic"
)

// TemplateExecutor is an executor for a template
type TemplateExecuter struct {
	requests []protocols.Request
	options  *protocols.ExecutorOptions
	engine   TemplateEngine
	results  *atomic.Bool
}

// Both executer & Executor are correct spellings (its open to interpretation)

var _ protocols.Executer = &TemplateExecuter{}

// NewTemplateExecuter creates a new request TemplateExecuter for list of requests
func NewTemplateExecuter(requests []protocols.Request, options *protocols.ExecutorOptions) *TemplateExecuter {
	e := &TemplateExecuter{requests: requests, options: options, results: &atomic.Bool{}}
	if options.Flow != "" {
		e.engine = flow.NewFlowExecutor(requests, options, e.results)
	} else {
		e.engine = generic.NewGenericEngine(requests, options, e.results)
	}
	return e
}

// Compile compiles the execution generators preparing any requests possible.
func (e *TemplateExecuter) Compile() error {
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
	return e.engine.Compile()
}

// Requests returns the total number of requests the rule will perform
func (e *TemplateExecuter) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *TemplateExecuter) Execute(input *contextargs.Context) (bool, error) {
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
	err := e.engine.ExecuteWithResults(input, cliExecutorCallback)
	if lastMatcherEvent != nil {
		writeFailureCallback(lastMatcherEvent, e.options.Options.MatcherStatus)
	}
	return results.Load(), err
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *TemplateExecuter) ExecuteWithResults(input *contextargs.Context, callback protocols.OutputEventCallback) error {
	gologger.Info().Msgf("[%s] Running on %s\n", e.options.TemplateID, input.MetaInput.PrettyPrint())
	userCallback := func(event *output.InternalWrappedEvent) {
		if event != nil {
			callback(event)
		}
	}
	return e.engine.ExecuteWithResults(input, userCallback)
}
