package tmplexec

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan/events"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/generic"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/multiproto"
	"github.com/projectdiscovery/utils/errkit"
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
	e := &TemplateExecuter{requests: requests, options: options, results: &atomic.Bool{}}
	if options.Flow != "" {
		// we use a dummy input here because goal of flow executor at this point is to just check
		// syntax and other things are correct before proceeding to actual execution
		// during execution new instance of flow will be created as it is tightly coupled with lot of executor options
		p, err := compiler.WrapScriptNCompile(options.Flow, false)
		if err != nil {
			return nil, fmt.Errorf("could not compile flow: %s", err)
		}
		e.program = p
	} else {
		// only use generic if there is only 1 protocol with only 1 section
		if len(requests) == 1 {
			e.engine = generic.NewGenericEngine(requests, options, e.results)
		} else {
			e.engine = multiproto.NewMultiProtocol(requests, options, e.results)
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

					gologger.Warning().Msg(formattedErrorMessage)
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

	// === when nuclei is built with -tags=stats ===
	// Note: this is no-op (empty functions) when nuclei is built in normal or without -tags=stats
	events.AddScanEvent(events.ScanEvent{
		Target:       ctx.Input.MetaInput.Input,
		Time:         time.Now(),
		EventType:    events.ScanStarted,
		TemplateType: e.getTemplateType(),
		TemplateID:   e.options.TemplateID,
		TemplatePath: e.options.TemplatePath,
		MaxRequests:  e.Requests(),
	})
	defer func() {
		events.AddScanEvent(events.ScanEvent{
			Target:       ctx.Input.MetaInput.Input,
			Time:         time.Now(),
			EventType:    events.ScanFinished,
			TemplateType: e.getTemplateType(),
			TemplateID:   e.options.TemplateID,
			TemplatePath: e.options.TemplatePath,
			MaxRequests:  e.Requests(),
		})
	}()
	// ==== end of stats ====

	// executed contains status of execution if it was successfully executed or not
	// doesn't matter if it was matched or not
	executed := &atomic.Bool{}
	// matched in this case means something was exported / written to output
	matched := &atomic.Bool{}
	// callbackCalled tracks if the callback was called or not
	callbackCalled := &atomic.Bool{}
	defer func() {
		// it is essential to remove template context of `Scan i.e template x input pair`
		// since it is of no use after scan is completed (regardless of success or failure)
		e.options.RemoveTemplateCtx(ctx.Input.MetaInput)
	}()

	var lastMatcherEvent *output.InternalWrappedEvent
	writeFailureCallback := func(event *output.InternalWrappedEvent, matcherStatus bool) {
		if !matched.Load() && matcherStatus {
			if err := e.options.Output.WriteFailure(event); err != nil {
				gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
			}
			executed.CompareAndSwap(false, true)
		}
	}

	ctx.OnResult = func(event *output.InternalWrappedEvent) {
		callbackCalled.Store(true)
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
		if !event.HasOperatorResult() && event.InternalEvent != nil {
			lastMatcherEvent = event
		} else {
			var isGlobalMatchers bool
			isGlobalMatchers, _ = event.InternalEvent["global-matchers"].(bool)
			// NOTE(dwisiswant0): Don't store `matched` on a `global-matchers` template.
			// This will end up generating 2 events from the same `scan.ScanContext` if
			// one of the templates has `global-matchers` enabled. This way,
			// non-`global-matchers` templates can enter the `writeFailureCallback`
			// func to log failure output.
			wr := writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient)
			if wr && !isGlobalMatchers {
				matched.Store(true)
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
		flowexec, err := flow.NewFlowExecutor(e.requests, ctx, e.options, executed, e.program)
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
	ctx.LogError(errx)

	if lastMatcherEvent != nil {
		lastMatcherEvent.Lock()
		defer lastMatcherEvent.Unlock()

		lastMatcherEvent.InternalEvent["error"] = getErrorCause(ctx.GenerateErrorMessage())

		writeFailureCallback(lastMatcherEvent, e.options.Options.MatcherStatus)
	}

	//TODO: this is a hacky way to handle the case where the callback is not called and matcher-status is true.
	// This is a workaround and needs to be refactored.
	// Check if callback was never called and matcher-status is true
	if !callbackCalled.Load() && e.options.Options.MatcherStatus {
		fakeEvent := &output.InternalWrappedEvent{
			Results: []*output.ResultEvent{
				{
					TemplateID: e.options.TemplateID,
					Info:       e.options.TemplateInfo,
					Type:       e.getTemplateType(),
					Host:       ctx.Input.MetaInput.Input,
					Error:      getErrorCause(ctx.GenerateErrorMessage()),
				},
			},
			OperatorsResult: &operators.Result{
				Matched: false,
			},
		}
		writeFailureCallback(fakeEvent, e.options.Options.MatcherStatus)
	}

	return executed.Load() || matched.Load(), errx
}

// getErrorCause tries to parse the cause of given error
// this is legacy support due to use of errorutil in existing libraries
// but this should not be required once all libraries are updated
func getErrorCause(err error) string {
	if err == nil {
		return ""
	}
	errx := errkit.FromError(err)
	var cause error
	for _, e := range errx.Errors() {
		if e != nil && strings.Contains(e.Error(), "context deadline exceeded") {
			continue
		}
		cause = e
		break
	}
	if cause == nil {
		cause = errkit.Append(errkit.New("could not get error cause"), errx)
	}
	// parseScanError prettifies the error message and removes everything except the cause
	return parseScanError(cause.Error())
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *TemplateExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	var errx error
	if e.options.Flow != "" {
		flowexec, err := flow.NewFlowExecutor(e.requests, ctx, e.options, e.results, e.program)
		if err != nil {
			ctx.LogError(err)
			return nil, fmt.Errorf("could not create flow executor: %s", err)
		}
		if err := flowexec.Compile(); err != nil {
			ctx.LogError(err)
			return nil, err
		}
		errx = flowexec.ExecuteWithResults(ctx)
	} else {
		errx = e.engine.ExecuteWithResults(ctx)
	}
	if errx != nil {
		ctx.LogError(errx)
	}
	return ctx.GenerateResult(), errx
}

// getTemplateType returns the template type of the template
func (e *TemplateExecuter) getTemplateType() string {
	if len(e.requests) == 0 {
		return "null"
	}
	if e.options.Flow != "" {
		return "flow"
	}
	if len(e.requests) > 1 {
		return "multiprotocol"
	}
	return e.requests[0].Type().String()
}
