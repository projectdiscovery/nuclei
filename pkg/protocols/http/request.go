package http

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"moul.io/http2curl"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	fuzzStats "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httputils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/signerpool"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/nucleierr"
	"github.com/projectdiscovery/rawhttp"
	convUtil "github.com/projectdiscovery/utils/conversion"
	"github.com/projectdiscovery/utils/errkit"
	errorutil "github.com/projectdiscovery/utils/errors"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	unitutils "github.com/projectdiscovery/utils/unit"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	defaultMaxWorkers = 150
	// max unique errors to store & combine
	// when executing requests in parallel
	maxErrorsWhenParallel = 3
)

var (
	MaxBodyRead = 10 * unitutils.Mega
	// ErrMissingVars is error occured when variables are missing
	ErrMissingVars = errkit.New("stop execution due to unresolved variables").SetKind(nucleierr.ErrTemplateLogic).Build()
	// ErrHttpEngineRequestDeadline is error occured when request deadline set by http request engine is exceeded
	ErrHttpEngineRequestDeadline = errkit.New("http request engine deadline exceeded").SetKind(errkit.ErrKindDeadline).Build()
)

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HTTPProtocol
}

// executeRaceRequest executes race condition request for a URL
func (request *Request) executeRaceRequest(input *contextargs.Context, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	reqURL := input.MetaInput.Input
	var generatedRequests []*generatedRequest

	// Requests within race condition should be dumped once and the output prefilled to allow DSL language to work
	// This will introduce a delay and will populate in hacky way the field "request" of outputEvent
	generator := request.newGenerator(false)

	inputData, payloads, ok := generator.nextValue()
	if !ok {
		return nil
	}
	ctx := request.newContext(input)
	requestForDump, err := generator.Make(ctx, input, inputData, payloads, nil)
	if err != nil {
		return err
	}
	request.setCustomHeaders(requestForDump)
	dumpedRequest, err := dump(requestForDump, reqURL)
	if err != nil {
		return err
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped HTTP request for %s\n\n", request.options.TemplateID, reqURL)
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Msg(msg)
			gologger.Print().Msgf("%s", string(dumpedRequest))
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(reqURL, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, dumpedRequest))
		}
	}
	previous["request"] = string(dumpedRequest)

	// Pre-Generate requests
	for i := 0; i < request.RaceNumberRequests; i++ {
		generator := request.newGenerator(false)
		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}
		ctx := request.newContext(input)
		generatedRequest, err := generator.Make(ctx, input, inputData, payloads, nil)
		if err != nil {
			return err
		}
		generatedRequests = append(generatedRequests, generatedRequest)
	}

	shouldStop := (request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch || request.options.StopAtFirstMatch)

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spmHandler := httputils.NewNonBlockingSPMHandler[error](childCtx, maxErrorsWhenParallel, shouldStop)
	defer spmHandler.Cancel()

	gotMatches := &atomic.Bool{}
	// wrappedCallback is a callback that wraps the original callback
	// to implement stop at first match logic
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if !event.HasOperatorResult() {
			callback(event) // not required but we can allow it
			return
		}
		// this will execute match condition such that if stop at first match is enabled
		// this will be only executed once
		spmHandler.MatchCallback(func() {
			gotMatches.Store(true)
			callback(event)
		})
		if shouldStop {
			// stop all running requests and exit
			spmHandler.Trigger()
		}
	}

	// look for unresponsive hosts and cancel inflight requests as well
	spmHandler.SetOnResultCallback(func(err error) {
		// marks thsi host as unresponsive if applicable
		request.markHostError(input, err)
		if request.isUnresponsiveAddress(input) {
			// stop all inflight requests
			spmHandler.Cancel()
		}
	})

	for i := 0; i < request.RaceNumberRequests; i++ {
		if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(input) {
			// stop sending more requests condition is met
			break
		}
		spmHandler.Acquire()
		// execute http request
		go func(httpRequest *generatedRequest) {
			defer spmHandler.Release()
			if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(input) {
				// stop sending more requests condition is met
				return
			}

			select {
			case <-spmHandler.Done():
				return
			case spmHandler.ResultChan <- request.executeRequest(input, httpRequest, previous, false, wrappedCallback, 0):
				return
			}
		}(generatedRequests[i])
		request.options.Progress.IncrementRequests()
	}
	spmHandler.Wait()

	if spmHandler.FoundFirstMatch() {
		// ignore any context cancellation and in-transit execution errors
		return nil
	}
	return multierr.Combine(spmHandler.CombinedResults()...)
}

// executeRaceRequest executes parallel requests for a template
func (request *Request) executeParallelHTTP(input *contextargs.Context, dynamicValues output.InternalEvent, callback protocols.OutputEventCallback) error {
	// Workers that keeps enqueuing new requests
	maxWorkers := request.Threads

	// if request threads matches global payload concurrency we follow it
	shouldFollowGlobal := maxWorkers == request.options.Options.PayloadConcurrency

	if protocolstate.IsLowOnMemory() {
		maxWorkers = protocolstate.GuardThreadsOrDefault(request.Threads)
	}

	// Stop-at-first-match logic while executing requests
	// parallely using threads
	shouldStop := (request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch || request.options.StopAtFirstMatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spmHandler := httputils.NewBlockingSPMHandler[error](ctx, maxWorkers, maxErrorsWhenParallel, shouldStop)
	defer spmHandler.Cancel()

	// wrappedCallback is a callback that wraps the original callback
	// to implement stop at first match logic
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if !event.HasOperatorResult() {
			callback(event) // not required but we can allow it
			return
		}
		// this will execute match condition such that if stop at first match is enabled
		// this will be only executed once
		spmHandler.MatchCallback(func() {
			callback(event)
		})
		if shouldStop {
			// stop all running requests and exit
			spmHandler.Trigger()
		}
	}

	// look for unresponsive hosts and cancel inflight requests as well
	spmHandler.SetOnResultCallback(func(err error) {
		// marks thsi host as unresponsive if applicable
		request.markHostError(input, err)
		if request.isUnresponsiveAddress(input) {
			// stop all inflight requests
			spmHandler.Cancel()
		}
	})

	// iterate payloads and make requests
	generator := request.newGenerator(false)
	for {
		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}

		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		// resize check point - nop if there are no changes
		if shouldFollowGlobal && spmHandler.Size() != request.options.Options.PayloadConcurrency {
			if err := spmHandler.Resize(input.Context(), request.options.Options.PayloadConcurrency); err != nil {
				return err
			}
		}

		// break if stop at first match is found or host is unresponsive
		if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(input) {
			break
		}

		ctx := request.newContext(input)
		generatedHttpRequest, err := generator.Make(ctx, input, inputData, payloads, dynamicValues)
		if err != nil {
			if err == types.ErrNoMoreRequests {
				break
			}
			request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		if input.MetaInput.Input == "" {
			input.MetaInput.Input = generatedHttpRequest.URL()
		}
		updatedInput := contextargs.GetCopyIfHostOutdated(input, generatedHttpRequest.URL())
		if request.isUnresponsiveAddress(updatedInput) {
			// skip on unresponsive host no need to continue
			spmHandler.Cancel()
			return nil
		}
		spmHandler.Acquire()
		go func(httpRequest *generatedRequest) {
			defer spmHandler.Release()
			if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(updatedInput) || spmHandler.Cancelled() {
				return
			}
			// putting ratelimiter here prevents any unnecessary waiting if any
			request.options.RateLimitTake()

			// after ratelimit take, check if we need to stop
			if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(updatedInput) || spmHandler.Cancelled() {
				return
			}

			select {
			case <-spmHandler.Done():
				return
			case spmHandler.ResultChan <- request.executeRequest(input, httpRequest, make(map[string]interface{}), false, wrappedCallback, 0):
				return
			}
		}(generatedHttpRequest)
		request.options.Progress.IncrementRequests()
	}
	spmHandler.Wait()
	if spmHandler.FoundFirstMatch() {
		// ignore any context cancellation and in-transit execution errors
		return nil
	}
	return multierr.Combine(spmHandler.CombinedResults()...)
}

// executeTurboHTTP executes turbo http request for a URL
func (request *Request) executeTurboHTTP(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := request.newGenerator(false)

	// need to extract the target from the url
	URL, err := urlutil.Parse(input.MetaInput.Input)
	if err != nil {
		return err
	}

	pipeOptions := rawhttp.DefaultPipelineOptions
	pipeOptions.Host = URL.Host
	pipeOptions.MaxConnections = 1
	if request.PipelineConcurrentConnections > 0 {
		pipeOptions.MaxConnections = request.PipelineConcurrentConnections
	}
	if request.PipelineRequestsPerConnection > 0 {
		pipeOptions.MaxPendingRequests = request.PipelineRequestsPerConnection
	}
	pipeClient := rawhttp.NewPipelineClient(pipeOptions)

	// defaultMaxWorkers should be a sufficient value to keep queues always full
	maxWorkers := defaultMaxWorkers
	// in case the queue is bigger increase the workers
	if pipeOptions.MaxPendingRequests > maxWorkers {
		maxWorkers = pipeOptions.MaxPendingRequests
	}

	// Stop-at-first-match logic while executing requests
	// parallely using threads
	shouldStop := (request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch || request.options.StopAtFirstMatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spmHandler := httputils.NewBlockingSPMHandler[error](ctx, maxWorkers, maxErrorsWhenParallel, shouldStop)
	defer spmHandler.Cancel()

	// wrappedCallback is a callback that wraps the original callback
	// to implement stop at first match logic
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if !event.HasOperatorResult() {
			callback(event) // not required but we can allow it
			return
		}
		// this will execute match condition such that if stop at first match is enabled
		// this will be only executed once
		spmHandler.MatchCallback(func() {
			callback(event)
		})
		if shouldStop {
			// stop all running requests and exit
			spmHandler.Trigger()
		}
	}

	// look for unresponsive hosts and cancel inflight requests as well
	spmHandler.SetOnResultCallback(func(err error) {
		// marks thsi host as unresponsive if applicable
		request.markHostError(input, err)
		if request.isUnresponsiveAddress(input) {
			// stop all inflight requests
			spmHandler.Cancel()
		}
	})

	for {
		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}

		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(input) || spmHandler.Cancelled() {
			// skip if first match is found
			break
		}

		ctx := request.newContext(input)
		generatedHttpRequest, err := generator.Make(ctx, input, inputData, payloads, dynamicValues)
		if err != nil {
			request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		if input.MetaInput.Input == "" {
			input.MetaInput.Input = generatedHttpRequest.URL()
		}
		updatedInput := contextargs.GetCopyIfHostOutdated(input, generatedHttpRequest.URL())
		if request.isUnresponsiveAddress(updatedInput) {
			// skip on unresponsive host no need to continue
			spmHandler.Cancel()
			return nil
		}
		generatedHttpRequest.pipelinedClient = pipeClient
		spmHandler.Acquire()
		go func(httpRequest *generatedRequest) {
			defer spmHandler.Release()
			if spmHandler.FoundFirstMatch() || request.isUnresponsiveAddress(updatedInput) {
				// skip if first match is found
				return
			}
			select {
			case <-spmHandler.Done():
				return
			case spmHandler.ResultChan <- request.executeRequest(input, httpRequest, previous, false, wrappedCallback, 0):
				return
			}
		}(generatedHttpRequest)
		request.options.Progress.IncrementRequests()
	}
	spmHandler.Wait()
	if spmHandler.FoundFirstMatch() {
		// ignore any context cancellation and in-transit execution errors
		return nil
	}
	return multierr.Combine(spmHandler.CombinedResults()...)
}

// ExecuteWithResults executes the final request on a URL
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if request.Pipeline || request.Race && request.RaceNumberRequests > 0 || request.Threads > 0 {
		variablesMap := request.options.Variables.Evaluate(generators.MergeMaps(dynamicValues, previous))
		dynamicValues = generators.MergeMaps(variablesMap, dynamicValues, request.options.Constants)
	}
	// verify if pipeline was requested
	if request.Pipeline {
		return request.executeTurboHTTP(input, dynamicValues, previous, callback)
	}
	// verify if a basic race condition was requested
	if request.Race && request.RaceNumberRequests > 0 {
		return request.executeRaceRequest(input, dynamicValues, callback)
	}

	// verify if fuzz elaboration was requested
	if len(request.Fuzzing) > 0 {
		return request.executeFuzzingRule(input, dynamicValues, callback)
	}

	// verify if parallel elaboration was requested
	if request.Threads > 0 && len(request.Payloads) > 0 {
		return request.executeParallelHTTP(input, dynamicValues, callback)
	}

	generator := request.newGenerator(false)

	var gotDynamicValues map[string][]string
	var requestErr error

	for {
		// returns two values, error and skip, which skips the execution for the request instance.
		executeFunc := func(data string, payloads, dynamicValue map[string]interface{}) (bool, error) {
			hasInteractMatchers := interactsh.HasMatchers(request.CompiledOperators)

			request.options.RateLimitTake()

			ctx := request.newContext(input)
			ctxWithTimeout, cancel := context.WithTimeoutCause(ctx, request.options.Options.GetTimeouts().HttpTimeout, ErrHttpEngineRequestDeadline)
			defer cancel()

			generatedHttpRequest, err := generator.Make(ctxWithTimeout, input, data, payloads, dynamicValue)
			if err != nil {
				if err == types.ErrNoMoreRequests {
					return true, nil
				}
				request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
				return true, err
			}
			// ideally if http template used a custom port or hostname
			// we would want to update it in input but currently templateCtx logic
			// is closely tied to contextargs.Context so we are temporarily creating
			// a copy and using it to check for host errors etc
			// but this should be replaced once templateCtx is refactored properly
			updatedInput := contextargs.GetCopyIfHostOutdated(input, generatedHttpRequest.URL())

			if generatedHttpRequest.customCancelFunction != nil {
				defer generatedHttpRequest.customCancelFunction()
			}

			hasInteractMarkers := interactsh.HasMarkers(data) || len(generatedHttpRequest.interactshURLs) > 0
			if input.MetaInput.Input == "" {
				input.MetaInput.Input = generatedHttpRequest.URL()
			}
			// Check if hosts keep erroring
			if request.isUnresponsiveAddress(updatedInput) {
				return true, nil
			}
			var gotMatches bool
			execReqErr := request.executeRequest(input, generatedHttpRequest, previous, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
				// a special case where operators has interactsh matchers and multiple request are made
				// ex: status_code_2 , interactsh_protocol (from 1st request) etc
				needsRequestEvent := interactsh.HasMatchers(request.CompiledOperators) && request.NeedsRequestCondition()
				if (hasInteractMarkers || needsRequestEvent) && request.options.Interactsh != nil {
					requestData := &interactsh.RequestData{
						MakeResultFunc: request.MakeResultEvent,
						Event:          event,
						Operators:      request.CompiledOperators,
						MatchFunc:      request.Match,
						ExtractFunc:    request.Extract,
					}
					allOASTUrls := httputils.GetInteractshURLSFromEvent(event.InternalEvent)
					allOASTUrls = append(allOASTUrls, generatedHttpRequest.interactshURLs...)
					request.options.Interactsh.RequestEvent(sliceutil.Dedupe(allOASTUrls), requestData)
					gotMatches = request.options.Interactsh.AlreadyMatched(requestData)
				}
				// Add the extracts to the dynamic values if any.
				if event.OperatorsResult != nil {
					gotMatches = event.OperatorsResult.Matched
					gotDynamicValues = generators.MergeMapsMany(event.OperatorsResult.DynamicValues, dynamicValues, gotDynamicValues)
				}
				// Note: This is a race condition prone zone i.e when request has interactsh_matchers
				// Interactsh.RequestEvent tries to access/update output.InternalWrappedEvent depending on logic
				// to avoid conflicts with `callback` mutex is used here and in Interactsh.RequestEvent
				// Note: this only happens if requests > 1 and interactsh matcher is used
				// TODO: interactsh logic in nuclei needs to be refactored to avoid such situations
				callback(event)
			}, generator.currentIndex)

			// If a variable is unresolved, skip all further requests
			if errors.Is(execReqErr, ErrMissingVars) {
				return true, nil
			}
			if execReqErr != nil {
				// if applicable mark the host as unresponsive
				requestErr = errorutil.NewWithErr(execReqErr).Msgf("got err while executing %v", generatedHttpRequest.URL())
				request.options.Progress.IncrementFailedRequestsBy(1)
			} else {
				request.options.Progress.IncrementRequests()
			}
			request.markHostError(updatedInput, execReqErr)

			// If this was a match, and we want to stop at first match, skip all further requests.
			shouldStopAtFirstMatch := generatedHttpRequest.original.options.Options.StopAtFirstMatch || generatedHttpRequest.original.options.StopAtFirstMatch || request.StopAtFirstMatch
			if shouldStopAtFirstMatch && gotMatches {
				return true, nil
			}
			return false, nil
		}

		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}

		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		var gotErr error
		var skip bool
		if len(gotDynamicValues) > 0 {
			operators.MakeDynamicValuesCallback(gotDynamicValues, request.IterateAll, func(data map[string]interface{}) bool {
				if skip, gotErr = executeFunc(inputData, payloads, data); skip || gotErr != nil {
					return true
				}
				return false
			})
		} else {
			skip, gotErr = executeFunc(inputData, payloads, dynamicValues)
		}
		if gotErr != nil && requestErr == nil {
			requestErr = gotErr
		}
		if skip || gotErr != nil {
			break
		}
	}
	return requestErr
}

const drainReqSize = int64(8 * unitutils.Kilo)

// executeRequest executes the actual generated request and returns error if occurred
func (request *Request) executeRequest(input *contextargs.Context, generatedRequest *generatedRequest, previousEvent output.InternalEvent, hasInteractMatchers bool, processEvent protocols.OutputEventCallback, requestCount int) (err error) {
	// Check if hosts keep erroring
	if request.isUnresponsiveAddress(input) {
		return fmt.Errorf("hostErrorsCache : host %s is unresponsive", input.MetaInput.Input)
	}

	// wrap one more callback for validation and fixing event
	callback := func(event *output.InternalWrappedEvent) {
		// validateNFixEvent performs necessary validation on generated event
		// and attempts to fix it , this includes things like making sure
		// `template-id` is set , `request-url-pattern` is set etc
		request.validateNFixEvent(input, generatedRequest, err, event)
		processEvent(event)
	}

	request.setCustomHeaders(generatedRequest)

	// Try to evaluate any payloads before replacement
	finalMap := generators.MergeMaps(generatedRequest.dynamicValues, generatedRequest.meta)

	// add known variables from metainput
	if _, ok := finalMap["ip"]; !ok && input.MetaInput.CustomIP != "" {
		finalMap["ip"] = input.MetaInput.CustomIP
	}

	for payloadName, payloadValue := range generatedRequest.meta {
		if data, err := expressions.Evaluate(types.ToString(payloadValue), finalMap); err == nil {
			generatedRequest.meta[payloadName] = data
		}
	}

	var (
		resp          *http.Response
		fromCache     bool
		dumpedRequest []byte
	)

	// Dump request for variables checks
	// For race conditions we can't dump the request body at this point as it's already waiting the open-gate event, already handled with a similar code within the race function
	if !generatedRequest.original.Race {

		// change encoding type to content-length unless transfer-encoding header is manually set
		if generatedRequest.request != nil && !stringsutil.EqualFoldAny(generatedRequest.request.Method, http.MethodGet, http.MethodHead) && generatedRequest.request.Body != nil && generatedRequest.request.Header.Get("Transfer-Encoding") != "chunked" {
			var newReqBody *reader.ReusableReadCloser
			newReqBody, ok := generatedRequest.request.Body.(*reader.ReusableReadCloser)
			if !ok {
				newReqBody, err = reader.NewReusableReadCloser(generatedRequest.request.Body)
			}
			if err == nil {
				// update the request body with the reusable reader
				generatedRequest.request.Body = newReqBody
				// get content length
				length, _ := io.Copy(io.Discard, newReqBody)
				generatedRequest.request.ContentLength = length
			} else {
				// log error and continue
				gologger.Verbose().Msgf("[%v] Could not read request body while forcing transfer encoding: %s\n", request.options.TemplateID, err)
				err = nil
			}
		}

		// do the same for unsafe requests
		if generatedRequest.rawRequest != nil && !stringsutil.EqualFoldAny(generatedRequest.rawRequest.Method, http.MethodGet, http.MethodHead) && generatedRequest.rawRequest.Data != "" && generatedRequest.rawRequest.Headers["Transfer-Encoding"] != "chunked" {
			generatedRequest.rawRequest.Headers["Content-Length"] = strconv.Itoa(len(generatedRequest.rawRequest.Data))
		}

		var dumpError error
		// TODO: dump is currently not working with post-processors - somehow it alters the signature
		dumpedRequest, dumpError = dump(generatedRequest, input.MetaInput.Input)
		if dumpError != nil {
			return dumpError
		}
		dumpedRequestString := string(dumpedRequest)

		if ignoreList := GetVariablesNamesSkipList(generatedRequest.original.Signature.Value); ignoreList != nil {
			if varErr := expressions.ContainsVariablesWithIgnoreList(ignoreList, dumpedRequestString); varErr != nil && !request.SkipVariablesCheck {
				gologger.Warning().Msgf("[%s] Could not make http request for %s: %v\n", request.options.TemplateID, input.MetaInput.Input, varErr)
				return ErrMissingVars
			}
		} else { // Check if are there any unresolved variables. If yes, skip unless overridden by user.
			if varErr := expressions.ContainsUnresolvedVariables(dumpedRequestString); varErr != nil && !request.SkipVariablesCheck {
				gologger.Warning().Msgf("[%s] Could not make http request for %s: %v\n", request.options.TemplateID, input.MetaInput.Input, varErr)
				return ErrMissingVars
			}
		}
	}

	// === apply auth strategies ===
	if generatedRequest.request != nil && !request.SkipSecretFile {
		generatedRequest.ApplyAuth(request.options.AuthProvider)
	}

	var formedURL string
	var hostname string
	timeStart := time.Now()
	if generatedRequest.original.Pipeline {
		// if request is a pipeline request, use the pipelined client
		if generatedRequest.rawRequest != nil {
			formedURL = generatedRequest.rawRequest.FullURL
			if parsed, parseErr := urlutil.ParseURL(formedURL, true); parseErr == nil {
				hostname = parsed.Host
			}
			resp, err = generatedRequest.pipelinedClient.DoRaw(generatedRequest.rawRequest.Method, input.MetaInput.Input, generatedRequest.rawRequest.Path, generators.ExpandMapValues(generatedRequest.rawRequest.Headers), io.NopCloser(strings.NewReader(generatedRequest.rawRequest.Data)))
		} else if generatedRequest.request != nil {
			resp, err = generatedRequest.pipelinedClient.Dor(generatedRequest.request)
		}
	} else if generatedRequest.original.Unsafe && generatedRequest.rawRequest != nil {
		// if request is a unsafe request, use the rawhttp client
		formedURL = generatedRequest.rawRequest.FullURL
		// use request url as matched url if empty
		if formedURL == "" {
			urlx, err := urlutil.Parse(input.MetaInput.Input)
			if err != nil {
				formedURL = fmt.Sprintf("%s%s", input.MetaInput.Input, generatedRequest.rawRequest.Path)
			} else {
				_ = urlx.MergePath(generatedRequest.rawRequest.Path, true)
				formedURL = urlx.String()
			}
		}
		if parsed, parseErr := urlutil.ParseURL(formedURL, true); parseErr == nil {
			hostname = parsed.Host
		}
		options := *generatedRequest.original.rawhttpClient.Options
		options.FollowRedirects = request.Redirects
		options.CustomRawBytes = generatedRequest.rawRequest.UnsafeRawBytes
		options.ForceReadAllBody = request.ForceReadAllBody
		options.SNI = request.options.Options.SNI
		inputUrl := input.MetaInput.Input
		if url, err := urlutil.ParseURL(inputUrl, false); err == nil {
			url.Path = ""
			url.Params = urlutil.NewOrderedParams() // donot include query params
			// inputUrl should only contain scheme://host:port
			inputUrl = url.String()
		}
		formedURL = fmt.Sprintf("%s%s", inputUrl, generatedRequest.rawRequest.Path)

		// send rawhttp request and get response
		resp, err = httpclientpool.SendRawRequest(generatedRequest.original.rawhttpClient, &httpclientpool.RawHttpRequestOpts{
			Method:  generatedRequest.rawRequest.Method,
			URL:     inputUrl,
			Path:    generatedRequest.rawRequest.Path,
			Headers: generators.ExpandMapValues(generatedRequest.rawRequest.Headers),
			Body:    io.NopCloser(strings.NewReader(generatedRequest.rawRequest.Data)),
			Options: &options,
		})
	} else {
		//** For Normal requests **//
		hostname = generatedRequest.request.URL.Host
		formedURL = generatedRequest.request.URL.String()
		// if nuclei-project is available check if the request was already sent previously
		if request.options.ProjectFile != nil {
			// if unavailable fail silently
			fromCache = true
			resp, err = request.options.ProjectFile.Get(dumpedRequest)
			if err != nil {
				fromCache = false
			}
		}
		if resp == nil {
			if errSignature := request.handleSignature(generatedRequest); errSignature != nil {
				return errSignature
			}
			httpclient := request.httpClient

			// this will be assigned/updated if this specific request has a custom configuration
			var modifiedConfig *httpclientpool.Configuration

			// check for cookie related configuration
			if input.CookieJar != nil {
				connConfiguration := request.connConfiguration.Clone()
				connConfiguration.Connection.SetCookieJar(input.CookieJar)
				modifiedConfig = connConfiguration
			}
			// check for request updatedTimeout annotation
			updatedTimeout, ok := generatedRequest.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
			if ok {
				if modifiedConfig == nil {
					connConfiguration := request.connConfiguration.Clone()
					modifiedConfig = connConfiguration
				}
				modifiedConfig.ResponseHeaderTimeout = updatedTimeout.Timeout
			}

			if modifiedConfig != nil {
				client, err := httpclientpool.Get(request.options.Options, modifiedConfig)
				if err != nil {
					return errors.Wrap(err, "could not get http client")
				}
				httpclient = client
			}

			resp, err = httpclient.Do(generatedRequest.request)
		}
	}
	// use request url as matched url if empty
	if formedURL == "" {
		formedURL = input.MetaInput.Input
	}

	// converts whitespace and other chars that cannot be printed to url encoded values
	formedURL = urlutil.URLEncodeWithEscapes(formedURL)

	// Dump the requests containing all headers
	if !generatedRequest.original.Race {
		var dumpError error
		dumpedRequest, dumpError = dump(generatedRequest, input.MetaInput.Input)
		if dumpError != nil {
			return dumpError
		}
		dumpedRequestString := string(dumpedRequest)
		if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
			msg := fmt.Sprintf("[%s] Dumped HTTP request for %s\n\n", request.options.TemplateID, formedURL)

			if request.options.Options.Debug || request.options.Options.DebugRequests {
				gologger.Info().Msg(msg)
				gologger.Print().Msgf("%s", dumpedRequestString)
			}
			if request.options.Options.StoreResponse {
				request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, dumpedRequestString))
			}
		}
	}

	if err != nil {
		// rawhttp doesn't support draining response bodies.
		if resp != nil && resp.Body != nil && generatedRequest.rawRequest == nil && !generatedRequest.original.Pipeline {
			_, _ = io.CopyN(io.Discard, resp.Body, drainReqSize)
			resp.Body.Close()
		}
		request.options.Output.Request(request.options.TemplatePath, formedURL, request.Type().String(), err)
		request.options.Progress.IncrementErrorsBy(1)

		// In case of interactsh markers and request times out, still send
		// a callback event so in case we receive an interaction, correlation is possible.
		// Also, to log failed use-cases.
		outputEvent := request.responseToDSLMap(&http.Response{}, input.MetaInput.Input, formedURL, convUtil.String(dumpedRequest), "", "", "", 0, generatedRequest.meta)
		if i := strings.LastIndex(hostname, ":"); i != -1 {
			hostname = hostname[:i]
		}

		if input.MetaInput.CustomIP != "" {
			outputEvent["ip"] = input.MetaInput.CustomIP
		} else {
			outputEvent["ip"] = protocolstate.Dialer.GetDialedIP(hostname)
			// try getting cname
			request.addCNameIfAvailable(hostname, outputEvent)
		}

		if len(generatedRequest.interactshURLs) > 0 {
			// according to logic we only need to trigger a callback if interactsh was used
			// and request failed in hope that later on oast interaction will be received
			event := &output.InternalWrappedEvent{}
			if request.CompiledOperators != nil && request.CompiledOperators.HasDSL() {
				event.InternalEvent = outputEvent
			}
			callback(event)
		}
		return err
	}

	var curlCommand string
	if !request.Unsafe && resp != nil && generatedRequest.request != nil && resp.Request != nil && !request.Race {
		bodyBytes, _ := generatedRequest.request.BodyBytes()
		resp.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		command, err := http2curl.GetCurlCommand(generatedRequest.request.Request)
		if err == nil && command != nil {
			curlCommand = command.String()
		}
	}

	gologger.Verbose().Msgf("[%s] Sent HTTP request to %s", request.options.TemplateID, formedURL)
	request.options.Output.Request(request.options.TemplatePath, formedURL, request.Type().String(), err)

	duration := time.Since(timeStart)

	// define max body read limit
	maxBodylimit := MaxBodyRead // 10MB
	if request.MaxSize > 0 {
		maxBodylimit = request.MaxSize
	}
	if request.options.Options.ResponseReadSize != 0 {
		maxBodylimit = request.options.Options.ResponseReadSize
	}

	// respChain is http response chain that reads response body
	// efficiently by reusing buffers and does all decoding and optimizations
	respChain := httpUtils.NewResponseChain(resp, int64(maxBodylimit))
	defer respChain.Close() // reuse buffers

	// we only intend to log/save the final redirected response
	// i.e why we have to use sync.Once to ensure it's only done once
	var errx error
	onceFunc := sync.OnceFunc(func() {
		// if nuclei-project is enabled store the response if not previously done
		if request.options.ProjectFile != nil && !fromCache {
			if err := request.options.ProjectFile.Set(dumpedRequest, resp, respChain.Body().Bytes()); err != nil {
				errx = errors.Wrap(err, "could not store in project file")
			}
		}
	})

	// evaluate responses continiously until first redirect request in reverse order
	for respChain.Has() {
		// fill buffers, read response body and reuse connection
		if err := respChain.Fill(); err != nil {
			return errors.Wrap(err, "could not generate response chain")
		}

		// log request stats
		request.options.Output.RequestStatsLog(strconv.Itoa(respChain.Response().StatusCode), respChain.FullResponse().String())

		// save response to projectfile
		onceFunc()
		matchedURL := input.MetaInput.Input
		if generatedRequest.rawRequest != nil {
			if generatedRequest.rawRequest.FullURL != "" {
				matchedURL = generatedRequest.rawRequest.FullURL
			} else {
				matchedURL = formedURL
			}
		}
		if generatedRequest.request != nil {
			matchedURL = generatedRequest.request.URL.String()
		}
		// Give precedence to the final URL from response
		if respChain.Request() != nil {
			if responseURL := respChain.Request().URL.String(); responseURL != "" {
				matchedURL = responseURL
			}
		}

		finalEvent := make(output.InternalEvent)

		if request.Analyzer != nil {
			analyzer := analyzers.GetAnalyzer(request.Analyzer.Name)
			analysisMatched, analysisDetails, err := analyzer.Analyze(&analyzers.Options{
				FuzzGenerated:      generatedRequest.fuzzGeneratedRequest,
				HttpClient:         request.httpClient,
				ResponseTimeDelay:  duration,
				AnalyzerParameters: request.Analyzer.Parameters,
			})
			if err != nil {
				gologger.Warning().Msgf("Could not analyze response: %v\n", err)
			}
			if analysisMatched {
				finalEvent["analyzer_details"] = analysisDetails
				finalEvent["analyzer"] = true
			}
		}

		outputEvent := request.responseToDSLMap(respChain.Response(), input.MetaInput.Input, matchedURL, convUtil.String(dumpedRequest), respChain.FullResponse().String(), respChain.Body().String(), respChain.Headers().String(), duration, generatedRequest.meta)
		// add response fields to template context and merge templatectx variables to output event
		request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
		if request.options.HasTemplateCtx(input.MetaInput) {
			outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
		}
		if i := strings.LastIndex(hostname, ":"); i != -1 {
			hostname = hostname[:i]
		}
		outputEvent["curl-command"] = curlCommand
		if input.MetaInput.CustomIP != "" {
			outputEvent["ip"] = input.MetaInput.CustomIP
		} else {
			dialer := protocolstate.GetDialer()
			if dialer != nil {
				outputEvent["ip"] = dialer.GetDialedIP(hostname)
			}

			// try getting cname
			request.addCNameIfAvailable(hostname, outputEvent)
		}
		if request.options.Interactsh != nil {
			request.options.Interactsh.MakePlaceholders(generatedRequest.interactshURLs, outputEvent)
		}
		for k, v := range previousEvent {
			finalEvent[k] = v
		}
		for k, v := range outputEvent {
			finalEvent[k] = v
		}

		// Add to history the current request number metadata if asked by the user.
		if request.NeedsRequestCondition() {
			for k, v := range outputEvent {
				key := fmt.Sprintf("%s_%d", k, requestCount)
				if previousEvent != nil {
					previousEvent[key] = v
				}
				finalEvent[key] = v
			}
		}
		// prune signature internal values if any
		request.pruneSignatureInternalValues(generatedRequest.meta)

		interimEvent := generators.MergeMaps(generatedRequest.dynamicValues, finalEvent)
		isDebug := request.options.Options.Debug || request.options.Options.DebugResponse
		event := eventcreator.CreateEventWithAdditionalOptions(request, interimEvent, isDebug, func(internalWrappedEvent *output.InternalWrappedEvent) {
			internalWrappedEvent.OperatorsResult.PayloadValues = generatedRequest.meta
		})

		if hasInteractMatchers {
			event.UsesInteractsh = true
		}

		if request.options.GlobalMatchers.HasMatchers() {
			request.options.GlobalMatchers.Match(interimEvent, request.Match, request.Extract, isDebug, func(event output.InternalEvent, result *operators.Result) {
				callback(eventcreator.CreateEventWithOperatorResults(request, event, result))
			})
		}

		// if requrlpattern is enabled, only then it is reflected in result event else it is empty string
		// consult @Ice3man543 before changing this logic (context: vuln_hash)
		if request.options.ExportReqURLPattern {
			for _, v := range event.Results {
				v.ReqURLPattern = generatedRequest.requestURLPattern
			}
		}

		responseContentType := respChain.Response().Header.Get("Content-Type")
		isResponseTruncated := request.MaxSize > 0 && respChain.Body().Len() >= request.MaxSize
		dumpResponse(event, request, respChain.FullResponse().Bytes(), formedURL, responseContentType, isResponseTruncated, input.MetaInput.Input)

		callback(event)

		if request.options.FuzzStatsDB != nil && generatedRequest.fuzzGeneratedRequest.Request != nil {
			request.options.FuzzStatsDB.RecordResultEvent(fuzzStats.FuzzingEvent{
				URL:           input.MetaInput.Target(),
				TemplateID:    request.options.TemplateID,
				ComponentType: generatedRequest.fuzzGeneratedRequest.Component.Name(),
				ComponentName: generatedRequest.fuzzGeneratedRequest.Parameter,
				PayloadSent:   generatedRequest.fuzzGeneratedRequest.Value,
				StatusCode:    respChain.Response().StatusCode,
				Matched:       event.HasResults(),
				RawRequest:    string(dumpedRequest),
				RawResponse:   respChain.FullResponse().String(),
				Severity:      request.options.TemplateInfo.SeverityHolder.Severity.String(),
			})
		}

		// Skip further responses if we have stop-at-first-match and a match
		if (request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch || request.StopAtFirstMatch) && event.HasResults() {
			return nil
		}
		// proceed with previous response
		// we evaluate operators recursively for each response
		// until we reach the first redirect response
		if !respChain.Previous() {
			break
		}
	}
	// return project file save error if any
	return errx
}

// validateNFixEvent validates and fixes the event
// it adds any missing template-id and request-url-pattern
func (request *Request) validateNFixEvent(input *contextargs.Context, gr *generatedRequest, err error, event *output.InternalWrappedEvent) {
	if event != nil {
		if event.InternalEvent == nil {
			event.InternalEvent = make(map[string]interface{})
			event.InternalEvent["template-id"] = request.options.TemplateID
		}
		// add the request URL pattern to the event
		event.InternalEvent[ReqURLPatternKey] = gr.requestURLPattern
		if event.InternalEvent["host"] == nil {
			event.InternalEvent["host"] = input.MetaInput.Input
		}
		if event.InternalEvent["template-id"] == nil {
			event.InternalEvent["template-id"] = request.options.TemplateID
		}
		if event.InternalEvent["type"] == nil {
			event.InternalEvent["type"] = request.Type().String()
		}
		if event.InternalEvent["template-path"] == nil {
			event.InternalEvent["template-path"] = request.options.TemplatePath
		}
		if event.InternalEvent["template-info"] == nil {
			event.InternalEvent["template-info"] = request.options.TemplateInfo
		}
		if err != nil {
			event.InternalEvent["error"] = err.Error()
		}
	}
}

// addCNameIfAvailable adds the cname to the event if available
func (request *Request) addCNameIfAvailable(hostname string, outputEvent map[string]interface{}) {
	if protocolstate.Dialer == nil {
		return
	}

	data, err := protocolstate.Dialer.GetDNSData(hostname)
	if err == nil {
		switch len(data.CNAME) {
		case 0:
			return
		case 1:
			outputEvent["cname"] = data.CNAME[0]
		default:
			// add 1st and put others in cname_all
			outputEvent["cname"] = data.CNAME[0]
			outputEvent["cname_all"] = data.CNAME
		}
	}
}

// handleSignature of the http request
func (request *Request) handleSignature(generatedRequest *generatedRequest) error {
	switch request.Signature.Value {
	case AWSSignature:
		var awsSigner signer.Signer
		allvars := generators.MergeMaps(request.options.Options.Vars.AsMap(), generatedRequest.dynamicValues)
		awsopts := signer.AWSOptions{
			AwsID:          types.ToString(allvars["aws-id"]),
			AwsSecretToken: types.ToString(allvars["aws-secret"]),
		}
		awsSigner, err := signerpool.Get(request.options.Options, &signerpool.Configuration{SignerArgs: &awsopts})
		if err != nil {
			return err
		}
		ctx := signer.GetCtxWithArgs(allvars, signer.AwsDefaultVars)
		err = awsSigner.SignHTTP(ctx, generatedRequest.request.Request)
		if err != nil {
			return err
		}
	}

	return nil
}

// setCustomHeaders sets the custom headers for generated request
func (request *Request) setCustomHeaders(req *generatedRequest) {
	for k, v := range request.customHeaders {
		if req.rawRequest != nil {
			req.rawRequest.Headers[k] = v
		} else {
			kk, vv := strings.TrimSpace(k), strings.TrimSpace(v)
			// NOTE(dwisiswant0): Do we really not need to convert it first into
			// lowercase?
			if kk == "Host" {
				req.request.Host = vv

				continue
			}

			req.request.Header[kk] = []string{vv}
		}
	}
}

const CRLF = "\r\n"

func dumpResponse(event *output.InternalWrappedEvent, request *Request, redirectedResponse []byte, formedURL string, responseContentType string, isResponseTruncated bool, reqURL string) {
	cliOptions := request.options.Options
	if cliOptions.Debug || cliOptions.DebugResponse || cliOptions.StoreResponse {
		response := string(redirectedResponse)

		var highlightedResult string
		if responseContentType == "application/octet-stream" || ((responseContentType == "" || responseContentType == "application/x-www-form-urlencoded") && responsehighlighter.HasBinaryContent(response)) {
			highlightedResult = createResponseHexDump(event, response, cliOptions.NoColor)
		} else {
			highlightedResult = responsehighlighter.Highlight(event.OperatorsResult, response, cliOptions.NoColor, false)
		}

		msg := "[%s] Dumped HTTP response %s\n\n%s"
		if isResponseTruncated {
			msg = "[%s] Dumped HTTP response (Truncated) %s\n\n%s"
		}
		fMsg := fmt.Sprintf(msg, request.options.TemplateID, formedURL, highlightedResult)
		if cliOptions.Debug || cliOptions.DebugResponse {
			gologger.Debug().Msg(fMsg)
		}
		if cliOptions.StoreResponse {
			request.options.Output.WriteStoreDebugData(reqURL, request.options.TemplateID, request.Type().String(), fMsg)
		}
	}
}

func createResponseHexDump(event *output.InternalWrappedEvent, response string, noColor bool) string {
	CRLFs := CRLF + CRLF
	headerEndIndex := strings.Index(response, CRLFs) + len(CRLFs)
	if headerEndIndex > 0 {
		headers := response[0:headerEndIndex]
		responseBodyHexDump := hex.Dump([]byte(response[headerEndIndex:]))

		highlightedHeaders := responsehighlighter.Highlight(event.OperatorsResult, headers, noColor, false)
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, responseBodyHexDump, noColor, true)
		return fmt.Sprintf("%s\n%s", highlightedHeaders, highlightedResponse)
	} else {
		return responsehighlighter.Highlight(event.OperatorsResult, hex.Dump([]byte(response)), noColor, true)
	}
}

func (request *Request) pruneSignatureInternalValues(maps ...map[string]interface{}) {
	var signatureFieldsToSkip map[string]interface{}
	switch request.Signature.Value {
	case AWSSignature:
		signatureFieldsToSkip = signer.AwsInternalOnlyVars
	default:
		return
	}

	for _, m := range maps {
		for fieldName := range signatureFieldsToSkip {
			delete(m, fieldName)
		}
	}
}

func (request *Request) newContext(input *contextargs.Context) context.Context {
	if input.MetaInput.CustomIP != "" {
		return context.WithValue(input.Context(), fastdialer.IP, input.MetaInput.CustomIP)
	}
	return input.Context()
}

// markHostError checks if the error is a unreponsive host error and marks it
func (request *Request) markHostError(input *contextargs.Context, err error) {
	if request.options.HostErrorsCache != nil {
		request.options.HostErrorsCache.MarkFailedOrRemove(request.options.ProtocolType.String(), input, err)
	}
}

// isUnresponsiveAddress checks if the error is a unreponsive based on its execution history
func (request *Request) isUnresponsiveAddress(input *contextargs.Context) bool {
	if request.options.HostErrorsCache != nil {
		return request.options.HostErrorsCache.Check(request.options.ProtocolType.String(), input)
	}
	return false
}
