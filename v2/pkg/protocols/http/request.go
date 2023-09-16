package http

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/multierr"
	"moul.io/http2curl"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/signerpool"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

const defaultMaxWorkers = 150

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

	wg := sync.WaitGroup{}
	var requestErr error
	mutex := &sync.Mutex{}
	for i := 0; i < request.RaceNumberRequests; i++ {
		wg.Add(1)
		go func(httpRequest *generatedRequest) {
			defer wg.Done()
			err := request.executeRequest(input, httpRequest, previous, false, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(generatedRequests[i])
		request.options.Progress.IncrementRequests()
	}
	wg.Wait()

	return requestErr
}

// executeRaceRequest executes parallel requests for a template
func (request *Request) executeParallelHTTP(input *contextargs.Context, dynamicValues output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := request.newGenerator(false)
	// Workers that keeps enqueuing new requests
	maxWorkers := request.Threads
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	mutex := &sync.Mutex{}
	for {
		inputData, payloads, ok := generator.nextValue()
		if !ok {
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
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			request.options.RateLimiter.Take()

			previous := make(map[string]interface{})
			err := request.executeRequest(input, httpRequest, previous, false, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(generatedHttpRequest)
		request.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
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
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	mutex := &sync.Mutex{}
	for {
		inputData, payloads, ok := generator.nextValue()
		if !ok {
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
		generatedHttpRequest.pipelinedClient = pipeClient
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			err := request.executeRequest(input, httpRequest, previous, false, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(generatedHttpRequest)
		request.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
}

// executeFuzzingRule executes fuzzing request for a URL
func (request *Request) executeFuzzingRule(input *contextargs.Context, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if _, err := urlutil.Parse(input.MetaInput.Input); err != nil {
		return errors.Wrap(err, "could not parse url")
	}
	fuzzRequestCallback := func(gr fuzz.GeneratedRequest) bool {
		hasInteractMatchers := interactsh.HasMatchers(request.CompiledOperators)
		hasInteractMarkers := len(gr.InteractURLs) > 0
		if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.Check(input.MetaInput.Input) {
			return false
		}
		request.options.RateLimiter.Take()
		req := &generatedRequest{
			request:        gr.Request,
			dynamicValues:  gr.DynamicValues,
			interactshURLs: gr.InteractURLs,
			original:       request,
		}
		var gotMatches bool
		requestErr := request.executeRequest(input, req, gr.DynamicValues, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
			if hasInteractMarkers && hasInteractMatchers && request.options.Interactsh != nil {
				requestData := &interactsh.RequestData{
					MakeResultFunc: request.MakeResultEvent,
					Event:          event,
					Operators:      request.CompiledOperators,
					MatchFunc:      request.Match,
					ExtractFunc:    request.Extract,
				}
				request.options.Interactsh.RequestEvent(gr.InteractURLs, requestData)
				gotMatches = request.options.Interactsh.AlreadyMatched(requestData)
			} else {
				callback(event)
			}
			// Add the extracts to the dynamic values if any.
			if event.OperatorsResult != nil {
				gotMatches = event.OperatorsResult.Matched
			}
		}, 0)
		// If a variable is unresolved, skip all further requests
		if errors.Is(requestErr, errStopExecution) {
			return false
		}
		if requestErr != nil {
			if request.options.HostErrorsCache != nil {
				request.options.HostErrorsCache.MarkFailed(input.MetaInput.Input, requestErr)
			}
		}
		request.options.Progress.IncrementRequests()

		// If this was a match, and we want to stop at first match, skip all further requests.
		shouldStopAtFirstMatch := request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch
		if shouldStopAtFirstMatch && gotMatches {
			return false
		}
		return true
	}

	// Iterate through all requests for template and queue them for fuzzing
	generator := request.newGenerator(true)
	for {
		value, payloads, result := generator.nextValue()
		if !result {
			break
		}
		generated, err := generator.Make(context.Background(), input, value, payloads, nil)
		if err != nil {
			continue
		}
		for _, rule := range request.Fuzzing {
			err = rule.Execute(&fuzz.ExecuteRuleInput{
				Input:       input,
				Callback:    fuzzRequestCallback,
				Values:      generated.dynamicValues,
				BaseRequest: generated.request,
			})
			if err == types.ErrNoMoreRequests {
				return nil
			}
			if err != nil {
				return errors.Wrap(err, "could not execute rule")
			}
		}
	}
	return nil
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

	// verify if parallel elaboration was requested
	if request.Threads > 0 {
		return request.executeParallelHTTP(input, dynamicValues, callback)
	}

	// verify if fuzz elaboration was requested
	if len(request.Fuzzing) > 0 {
		return request.executeFuzzingRule(input, dynamicValues, callback)
	}

	generator := request.newGenerator(false)

	var gotDynamicValues map[string][]string
	var requestErr error

	for {
		// returns two values, error and skip, which skips the execution for the request instance.
		executeFunc := func(data string, payloads, dynamicValue map[string]interface{}) (bool, error) {
			hasInteractMatchers := interactsh.HasMatchers(request.CompiledOperators)

			request.options.RateLimiter.Take()

			ctx := request.newContext(input)
			ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(request.options.Options.Timeout)*time.Second)
			defer cancel()
			generatedHttpRequest, err := generator.Make(ctxWithTimeout, input, data, payloads, dynamicValue)
			if err != nil {
				if err == types.ErrNoMoreRequests {
					return true, nil
				}
				request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
				return true, err
			}

			if generatedHttpRequest.customCancelFunction != nil {
				defer generatedHttpRequest.customCancelFunction()
			}

			hasInteractMarkers := interactsh.HasMarkers(data) || len(generatedHttpRequest.interactshURLs) > 0
			if input.MetaInput.Input == "" {
				input.MetaInput.Input = generatedHttpRequest.URL()
			}
			// Check if hosts keep erroring
			if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.Check(input.MetaInput.ID()) {
				return true, nil
			}
			var gotMatches bool
			err = request.executeRequest(input, generatedHttpRequest, previous, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
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
					allOASTUrls := getInteractshURLsFromEvent(event.InternalEvent)
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
			if errors.Is(err, errStopExecution) {
				return true, nil
			}
			if err != nil {
				if request.options.HostErrorsCache != nil {
					request.options.HostErrorsCache.MarkFailed(input.MetaInput.ID(), err)
				}
				requestErr = err
			}
			request.options.Progress.IncrementRequests()

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

const drainReqSize = int64(8 * 1024)

var errStopExecution = errors.New("stop execution due to unresolved variables")

// executeRequest executes the actual generated request and returns error if occurred
func (request *Request) executeRequest(input *contextargs.Context, generatedRequest *generatedRequest, previousEvent output.InternalEvent, hasInteractMatchers bool, callback protocols.OutputEventCallback, requestCount int) error {
	request.setCustomHeaders(generatedRequest)

	// Try to evaluate any payloads before replacement
	finalMap := generators.MergeMaps(generatedRequest.dynamicValues, generatedRequest.meta)

	// add known variables from metainput
	if _, ok := finalMap["ip"]; !ok && input.MetaInput.CustomIP != "" {
		finalMap["ip"] = input.MetaInput.CustomIP
	}

	for payloadName, payloadValue := range generatedRequest.dynamicValues {
		if data, err := expressions.Evaluate(types.ToString(payloadValue), finalMap); err == nil {
			generatedRequest.dynamicValues[payloadName] = data
		}
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
		err           error
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
				return errStopExecution
			}
		} else { // Check if are there any unresolved variables. If yes, skip unless overridden by user.
			if varErr := expressions.ContainsUnresolvedVariables(dumpedRequestString); varErr != nil && !request.SkipVariablesCheck {
				gologger.Warning().Msgf("[%s] Could not make http request for %s: %v\n", request.options.TemplateID, input.MetaInput.Input, varErr)
				return errStopExecution
			}
		}
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
		resp, err = generatedRequest.original.rawhttpClient.DoRawWithOptions(generatedRequest.rawRequest.Method, inputUrl, generatedRequest.rawRequest.Path, generators.ExpandMapValues(generatedRequest.rawRequest.Headers), io.NopCloser(strings.NewReader(generatedRequest.rawRequest.Data)), &options)
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
			if input.CookieJar != nil {
				connConfiguration := request.connConfiguration
				connConfiguration.Connection.SetCookieJar(input.CookieJar)
				client, err := httpclientpool.Get(request.options.Options, connConfiguration)
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

		// If we have interactsh markers and request times out, still send
		// a callback event so in case we receive an interaction, correlation is possible.
		if hasInteractMatchers {
			outputEvent := request.responseToDSLMap(&http.Response{}, input.MetaInput.Input, formedURL, tostring.UnsafeToString(dumpedRequest), "", "", "", 0, generatedRequest.meta)
			if i := strings.LastIndex(hostname, ":"); i != -1 {
				hostname = hostname[:i]
			}

			if input.MetaInput.CustomIP != "" {
				outputEvent["ip"] = input.MetaInput.CustomIP
			} else {
				outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)
			}

			event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
			if request.CompiledOperators != nil {
				event.InternalEvent = outputEvent
			}
			callback(event)
		}
		return err
	}
	defer func() {
		if resp.StatusCode != http.StatusSwitchingProtocols {
			_, _ = io.CopyN(io.Discard, resp.Body, drainReqSize)
		}
		resp.Body.Close()
	}()

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

	dumpedResponseHeaders, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return errors.Wrap(err, "could not dump http response")
	}

	var dumpedResponse []redirectedResponse
	var gotData []byte
	// If the status code is HTTP 101, we should not proceed with reading body.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		var bodyReader io.Reader
		if request.MaxSize != 0 {
			bodyReader = io.LimitReader(resp.Body, int64(request.MaxSize))
		} else if request.options.Options.ResponseReadSize != 0 {
			bodyReader = io.LimitReader(resp.Body, int64(request.options.Options.ResponseReadSize))
		} else {
			bodyReader = resp.Body
		}
		data, err := io.ReadAll(bodyReader)
		if err != nil {
			// Ignore body read due to server misconfiguration errors
			if stringsutil.ContainsAny(err.Error(), "gzip: invalid header") {
				gologger.Warning().Msgf("[%s] Server sent an invalid gzip header and it was not possible to read the uncompressed body for %s: %s", request.options.TemplateID, formedURL, err.Error())
			} else if !stringsutil.ContainsAny(err.Error(), "unexpected EOF", "user canceled") { // ignore EOF and random error
				return errors.Wrap(err, "could not read http body")
			}
		}
		gotData = data
		resp.Body.Close()

		dumpedResponse, err = dumpResponseWithRedirectChain(resp, data)
		if err != nil {
			return errors.Wrap(err, "could not read http response with redirect chain")
		}
	} else {
		dumpedResponse = []redirectedResponse{{resp: resp, fullResponse: dumpedResponseHeaders, headers: dumpedResponseHeaders}}
	}

	// if nuclei-project is enabled store the response if not previously done
	if request.options.ProjectFile != nil && !fromCache {
		if err := request.options.ProjectFile.Set(dumpedRequest, resp, gotData); err != nil {
			return errors.Wrap(err, "could not store in project file")
		}
	}

	for _, response := range dumpedResponse {
		if response.resp == nil {
			continue // Skip nil responses
		}
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
		if response.resp.Request != nil {
			if responseURL := response.resp.Request.URL.String(); responseURL != "" {
				matchedURL = responseURL
			}
		}
		finalEvent := make(output.InternalEvent)

		outputEvent := request.responseToDSLMap(response.resp, input.MetaInput.Input, matchedURL, tostring.UnsafeToString(dumpedRequest), tostring.UnsafeToString(response.fullResponse), tostring.UnsafeToString(response.body), tostring.UnsafeToString(response.headers), duration, generatedRequest.meta)
		if i := strings.LastIndex(hostname, ":"); i != -1 {
			hostname = hostname[:i]
		}
		outputEvent["curl-command"] = curlCommand
		if input.MetaInput.CustomIP != "" {
			outputEvent["ip"] = input.MetaInput.CustomIP
		} else {
			outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)
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
				previousEvent[key] = v
				finalEvent[key] = v
			}
		}
		// prune signature internal values if any
		request.pruneSignatureInternalValues(generatedRequest.meta)

		event := eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(generatedRequest.dynamicValues, finalEvent), request.options.Options.Debug || request.options.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
			internalWrappedEvent.OperatorsResult.PayloadValues = generatedRequest.meta
		})
		if hasInteractMatchers {
			event.UsesInteractsh = true
		}

		responseContentType := resp.Header.Get("Content-Type")
		isResponseTruncated := request.MaxSize > 0 && len(gotData) >= request.MaxSize
		dumpResponse(event, request, response.fullResponse, formedURL, responseContentType, isResponseTruncated, input.MetaInput.Input)

		callback(event)

		// Skip further responses if we have stop-at-first-match and a match
		if (request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch || request.StopAtFirstMatch) && event.HasResults() {
			return nil
		}
	}
	return nil
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
			req.request.Header.Set(kk, vv)
			if kk == "Host" {
				req.request.Host = vv
			}
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
		return context.WithValue(context.Background(), fastdialer.IP, input.MetaInput.CustomIP)
	}
	return context.Background()
}
