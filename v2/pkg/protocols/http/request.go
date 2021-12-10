package http

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/multierr"
	"moul.io/http2curl"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/stringsutil"
)

const defaultMaxWorkers = 150

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HTTPProtocol
}

// executeRaceRequest executes race condition request for a URL
func (request *Request) executeRaceRequest(reqURL string, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var generatedRequests []*generatedRequest

	// Requests within race condition should be dumped once and the output prefilled to allow DSL language to work
	// This will introduce a delay and will populate in hacky way the field "request" of outputEvent
	generator := request.newGenerator()

	inputData, payloads, ok := generator.nextValue()
	if !ok {
		return nil
	}
	requestForDump, err := generator.Make(reqURL, inputData, payloads, nil)
	if err != nil {
		return err
	}
	request.setCustomHeaders(requestForDump)
	dumpedRequest, err := dump(requestForDump, reqURL)
	if err != nil {
		return err
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", request.options.TemplateID, reqURL)
		gologger.Print().Msgf("%s", string(dumpedRequest))
	}
	previous["request"] = string(dumpedRequest)

	// Pre-Generate requests
	for i := 0; i < request.RaceNumberRequests; i++ {
		generator := request.newGenerator()
		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}
		generatedRequest, err := generator.Make(reqURL, inputData, payloads, nil)
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
			err := request.executeRequest(reqURL, httpRequest, previous, false, callback, 0)
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
func (request *Request) executeParallelHTTP(reqURL string, dynamicValues output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := request.newGenerator()

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
		generatedHttpRequest, err := generator.Make(reqURL, inputData, payloads, dynamicValues)
		if err != nil {
			if err == io.EOF {
				break
			}
			request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		if reqURL == "" {
			reqURL = generatedHttpRequest.URL()
		}
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			request.options.RateLimiter.Take()

			previous := make(map[string]interface{})
			err := request.executeRequest(reqURL, httpRequest, previous, false, callback, 0)
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
func (request *Request) executeTurboHTTP(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := request.newGenerator()

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
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
		generatedHttpRequest, err := generator.Make(reqURL, inputData, payloads, dynamicValues)
		if err != nil {
			request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		if reqURL == "" {
			reqURL = generatedHttpRequest.URL()
		}
		generatedHttpRequest.pipelinedClient = pipeClient
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			err := request.executeRequest(reqURL, httpRequest, previous, false, callback, 0)
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

// ExecuteWithResults executes the final request on a URL
func (request *Request) ExecuteWithResults(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// verify if pipeline was requested
	if request.Pipeline {
		return request.executeTurboHTTP(reqURL, dynamicValues, previous, callback)
	}

	// verify if a basic race condition was requested
	if request.Race && request.RaceNumberRequests > 0 {
		return request.executeRaceRequest(reqURL, previous, callback)
	}

	// verify if parallel elaboration was requested
	if request.Threads > 0 {
		return request.executeParallelHTTP(reqURL, dynamicValues, callback)
	}

	generator := request.newGenerator()

	var gotDynamicValues map[string][]string
	requestCount := 1
	var requestErr error
	for {
		// returns two values, error and skip, which skips the execution for the request instance.
		executeFunc := func(data string, payloads, dynamicValue map[string]interface{}) (bool, error) {
			hasInteractMarkers := interactsh.HasMatchers(request.CompiledOperators)

			generatedHttpRequest, err := generator.Make(reqURL, data, payloads, dynamicValue)
			if err != nil {
				if err == io.EOF {
					return true, nil
				}
				request.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
				return true, err
			}
			if reqURL == "" {
				reqURL = generatedHttpRequest.URL()
			}
			// Check if hosts keep erroring
			if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.Check(reqURL) {
				return true, nil
			}
			var gotOutput bool
			request.options.RateLimiter.Take()

			err = request.executeRequest(reqURL, generatedHttpRequest, previous, hasInteractMarkers, func(event *output.InternalWrappedEvent) {
				// Add the extracts to the dynamic values if any.
				if event.OperatorsResult != nil {
					gotOutput = true
					gotDynamicValues = generators.MergeMapsMany(event.OperatorsResult.DynamicValues, dynamicValues, gotDynamicValues)
				}
				if hasInteractMarkers && request.options.Interactsh != nil {
					request.options.Interactsh.RequestEvent(generatedHttpRequest.interactshURLs, &interactsh.RequestData{
						MakeResultFunc: request.MakeResultEvent,
						Event:          event,
						Operators:      request.CompiledOperators,
						MatchFunc:      request.Match,
						ExtractFunc:    request.Extract,
					})
				} else {
					callback(event)
				}
			}, requestCount)

			// If a variable is unresolved, skip all further requests
			if err == errStopExecution {
				return true, nil
			}
			if err != nil {
				if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.CheckError(err) {
					request.options.HostErrorsCache.MarkFailed(reqURL)
				}
				requestErr = err
			}
			requestCount++
			request.options.Progress.IncrementRequests()

			// If this was a match, and we want to stop at first match, skip all further requests.
			if (generatedHttpRequest.original.options.Options.StopAtFirstMatch || generatedHttpRequest.original.options.StopAtFirstMatch || request.StopAtFirstMatch) && gotOutput {
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
func (request *Request) executeRequest(reqURL string, generatedRequest *generatedRequest, previousEvent output.InternalEvent, hasInteractMarkers bool, callback protocols.OutputEventCallback, requestCount int) error {
	request.setCustomHeaders(generatedRequest)

	var (
		resp          *http.Response
		fromCache     bool
		dumpedRequest []byte
		err           error
	)

	// For race conditions we can't dump the request body at this point as it's already waiting the open-gate event, already handled with a similar code within the race function
	if !generatedRequest.original.Race {
		var dumpError error
		dumpedRequest, dumpError = dump(generatedRequest, reqURL)
		if dumpError != nil {
			return dumpError
		}
		dumpedRequestString := string(dumpedRequest)

		// Check if are there any unresolved variables. If yes, skip unless overridden by user.
		if varErr := expressions.ContainsUnresolvedVariables(dumpedRequestString); varErr != nil && !request.SkipVariablesCheck {
			gologger.Warning().Msgf("[%s] Could not make http request for %s: %v\n", request.options.TemplateID, reqURL, varErr)
			return errStopExecution
		}

		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", request.options.TemplateID, reqURL)
			gologger.Print().Msgf("%s", dumpedRequestString)
		}
	}
	var formedURL string
	var hostname string
	timeStart := time.Now()
	if generatedRequest.original.Pipeline {
		if generatedRequest.rawRequest != nil {
			formedURL = generatedRequest.rawRequest.FullURL
			if parsed, parseErr := url.Parse(formedURL); parseErr == nil {
				hostname = parsed.Host
			}
			resp, err = generatedRequest.pipelinedClient.DoRaw(generatedRequest.rawRequest.Method, reqURL, generatedRequest.rawRequest.Path, generators.ExpandMapValues(generatedRequest.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(generatedRequest.rawRequest.Data)))
		} else if generatedRequest.request != nil {
			resp, err = generatedRequest.pipelinedClient.Dor(generatedRequest.request)
		}
	} else if generatedRequest.original.Unsafe && generatedRequest.rawRequest != nil {
		formedURL = generatedRequest.rawRequest.FullURL
		if parsed, parseErr := url.Parse(formedURL); parseErr == nil {
			hostname = parsed.Host
		}
		options := generatedRequest.original.rawhttpClient.Options
		options.FollowRedirects = request.Redirects
		options.CustomRawBytes = generatedRequest.rawRequest.UnsafeRawBytes
		resp, err = generatedRequest.original.rawhttpClient.DoRawWithOptions(generatedRequest.rawRequest.Method, reqURL, generatedRequest.rawRequest.Path, generators.ExpandMapValues(generatedRequest.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(generatedRequest.rawRequest.Data)), options)
	} else {
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
			resp, err = request.httpClient.Do(generatedRequest.request)
		}
	}
	if err != nil {
		// rawhttp doesn't support draining response bodies.
		if resp != nil && resp.Body != nil && generatedRequest.rawRequest == nil {
			_, _ = io.CopyN(ioutil.Discard, resp.Body, drainReqSize)
			resp.Body.Close()
		}
		request.options.Output.Request(request.options.TemplatePath, formedURL, request.Type().String(), err)
		request.options.Progress.IncrementErrorsBy(1)

		// If we have interactsh markers and request times out, still send
		// a callback event so in case we receive an interaction, correlation is possible.
		if hasInteractMarkers {
			outputEvent := request.responseToDSLMap(&http.Response{}, reqURL, formedURL, tostring.UnsafeToString(dumpedRequest), "", "", "", 0, generatedRequest.meta)
			if i := strings.LastIndex(hostname, ":"); i != -1 {
				hostname = hostname[:i]
			}
			outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)

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
			_, _ = io.CopyN(ioutil.Discard, resp.Body, drainReqSize)
		}
		resp.Body.Close()
	}()

	var curlCommand string
	if !request.Unsafe && resp != nil && generatedRequest.request != nil && resp.Request != nil {
		bodyBytes, _ := generatedRequest.request.BodyBytes()
		resp.Request.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		command, _ := http2curl.GetCurlCommand(resp.Request)
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
		} else {
			bodyReader = resp.Body
		}
		data, err := ioutil.ReadAll(bodyReader)
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
		dumpedResponse = []redirectedResponse{{fullResponse: dumpedResponseHeaders, headers: dumpedResponseHeaders}}
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
		matchedURL := reqURL
		if generatedRequest.rawRequest != nil && generatedRequest.rawRequest.FullURL != "" {
			matchedURL = generatedRequest.rawRequest.FullURL
		}
		if generatedRequest.request != nil {
			matchedURL = generatedRequest.request.URL.String()
		}
		finalEvent := make(output.InternalEvent)

		dumpedRequestString := tostring.UnsafeToString(dumpedRequest)
		dumpedFullResponse := tostring.UnsafeToString(response.fullResponse)

		outputEvent := request.responseToDSLMap(response.resp, reqURL, matchedURL, dumpedRequestString, dumpedFullResponse, tostring.UnsafeToString(response.body), tostring.UnsafeToString(response.headers), duration, generatedRequest.meta)
		if i := strings.LastIndex(hostname, ":"); i != -1 {
			hostname = hostname[:i]
		}
		outputEvent["curl-command"] = curlCommand
		outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)
		for k, v := range previousEvent {
			finalEvent[k] = v
		}
		for k, v := range outputEvent {
			finalEvent[k] = v
		}
		// Add to history the current request number metadata if asked by the user.
		if request.ReqCondition {
			for k, v := range outputEvent {
				key := fmt.Sprintf("%s_%d", k, requestCount)
				previousEvent[key] = v
				finalEvent[key] = v
			}
		}
		debugEvent := output.DebugEvent{Request: dumpedRequestString, Response: dumpedFullResponse}

		event := eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(generatedRequest.dynamicValues, finalEvent), debugEvent, request.options.Options.Debug || request.options.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
			internalWrappedEvent.OperatorsResult.PayloadValues = generatedRequest.meta
		})
		if hasInteractMarkers {
			event.UsesInteractsh = true
		}

		responseContentType := resp.Header.Get("Content-Type")
		dumpResponse(event, request.options, response.fullResponse, formedURL, responseContentType)

		callback(event)
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

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, redirectedResponse []byte, formedURL string, responseContentType string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		response := string(redirectedResponse)

		var highlightedResult string
		if responseContentType == "application/octet-stream" || ((responseContentType == "" || responseContentType == "application/x-www-form-urlencoded") && responsehighlighter.HasBinaryContent(response)) {
			highlightedResult = createResponseHexDump(event, response, cliOptions.NoColor)
		} else {
			highlightedResult = responsehighlighter.Highlight(event.OperatorsResult, response, cliOptions.NoColor, false)
		}

		gologger.Debug().Msgf("[%s] Dumped HTTP response for %s\n\n%s", requestOptions.TemplateID, formedURL, highlightedResult)
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
