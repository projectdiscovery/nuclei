package tmplexec

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/generic"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/multiproto"
)

// TemplateExecutor is an executor for a template
type TemplateExecuter struct {
	requests []protocols.Request
	options  *protocols.ExecutorOptions
	engine   TemplateEngine
	results  *atomic.Bool
	program  *goja.Program
}

// Both executer & Executor are correct spellings (its open to interpretation)

var _ protocols.Executer = &TemplateExecuter{}

// NewTemplateExecuter creates a new request TemplateExecuter for list of requests
func NewTemplateExecuter(requests []protocols.Request, options *protocols.ExecutorOptions) (*TemplateExecuter, error) {
	isMultiProto := false
	lastProto := ""
	for _, request := range requests {
		if request.Type().String() != lastProto && lastProto != "" {
			isMultiProto = true
			break
		}
		lastProto = request.Type().String()
	}

	e := &TemplateExecuter{requests: requests, options: options, results: &atomic.Bool{}}
	if options.Flow != "" {
		// we use a dummy input here because goal of flow executor at this point is to just check
		// syntax and other things are correct before proceeding to actual execution
		// during execution new instance of flow will be created as it is tightly coupled with lot of executor options
		p, err := goja.Compile("flow.js", options.Flow, false)
		if err != nil {
			return nil, fmt.Errorf("could not compile flow: %s", err)
		}
		e.program = p
	} else {
		// Review:
		// multiproto engine is only used if there is more than one protocol in template
		// else we use generic engine (should we use multiproto engine for single protocol with multiple requests as well ?)
		if isMultiProto {
			e.engine = multiproto.NewMultiProtocol(requests, options, e.results)
		} else {
			e.engine = generic.NewGenericEngine(requests, options, e.results)
		}
	}
	return e, nil
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
	if e.engine == nil && e.options.Flow != "" {
		// this is true for flow executor
		return nil
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
func (e *TemplateExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	results := &atomic.Bool{}
	defer func() {
		// it is essential to remove template context of `Scan i.e template x input pair`
		// since it is of no use after scan is completed (regardless of success or failure)
		e.options.RemoveTemplateCtx(ctx.Input.MetaInput)
	}()

	var lastMatcherEvent *output.InternalWrappedEvent
	writeFailureCallback := func(event *output.InternalWrappedEvent, matcherStatus bool) {
		if !results.Load() && matcherStatus {
			if err := e.options.Output.WriteFailure(event); err != nil {
				gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
			}
			results.CompareAndSwap(false, true)
		}
	}

	ctx.OnResult = func(event *output.InternalWrappedEvent) {
		if event == nil {
			// something went wrong
			return
		}
		// check for internal true matcher event
		if event.HasOperatorResult() && event.OperatorsResult.Matched && event.OperatorsResult.Operators != nil {
			// note all matchers should have internal:true if it is a combination then print it
			allInternalMatchers := true
			for _, matcher := range event.OperatorsResult.Operators.Matchers {
				if allInternalMatchers && !matcher.Internal {
					allInternalMatchers = false
					break
				}
			}
			if allInternalMatchers {
				// this is a internal event and no meant to be printed
				return
			}
		}

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
	var errx error

	// Note: this is required for flow executor
	// flow executer is tightly coupled with lot of executor options
	// and map , wg and other types earlier we tried to use (compile once and run multiple times)
	// but it is causing lot of panic and nil pointer dereference issues
	// so in compile step earlier we compile it to validate javascript syntax and other things
	// and while executing we create new instance of flow executor everytime
	if e.options.Flow != "" {
		flowexec, err := flow.NewFlowExecutor(e.requests, ctx, e.options, results, e.program)
		if err != nil {
			ctx.LogError(err)
			return false, fmt.Errorf("could not create flow executor: %s", err)
		}
		if err := flowexec.Compile(); err != nil {
			ctx.LogError(err)
			return false, err
		}
		errx = flowexec.ExecuteWithResults(ctx)
	} else {
		errx = e.engine.ExecuteWithResults(ctx)
	}

	if lastMatcherEvent != nil {
		writeFailureCallback(lastMatcherEvent, e.options.Options.MatcherStatus)
	}
	return results.Load(), errx
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *TemplateExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	err := e.engine.ExecuteWithResults(ctx)
	ctx.LogError(err)
	return ctx.GenerateResult(), err
}
