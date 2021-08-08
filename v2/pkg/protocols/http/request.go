package http

import (
	"bytes"
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
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/stringsutil"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/multierr"
)

const defaultMaxWorkers = 150

// executeRaceRequest executes race condition request for a URL
func (r *Request) executeRaceRequest(reqURL string, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var requests []*generatedRequest

	// Requests within race condition should be dumped once and the output prefilled to allow DSL language to work
	// This will introduce a delay and will populate in hacky way the field "request" of outputEvent
	generator := r.newGenerator()
	requestForDump, err := generator.Make(reqURL, nil, "")
	if err != nil {
		return err
	}
	r.setCustomHeaders(requestForDump)
	dumpedRequest, err := dump(requestForDump, reqURL)
	if err != nil {
		return err
	}
	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", r.options.TemplateID, reqURL)
		gologger.Print().Msgf("%s", string(dumpedRequest))
	}
	previous["request"] = string(dumpedRequest)

	// Pre-Generate requests
	for i := 0; i < r.RaceNumberRequests; i++ {
		generator := r.newGenerator()
		request, err := generator.Make(reqURL, nil, "")
		if err != nil {
			return err
		}
		requests = append(requests, request)
	}

	wg := sync.WaitGroup{}
	var requestErr error
	mutex := &sync.Mutex{}
	for i := 0; i < r.RaceNumberRequests; i++ {
		wg.Add(1)
		go func(httpRequest *generatedRequest) {
			defer wg.Done()
			err := r.executeRequest(reqURL, httpRequest, previous, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(requests[i])
		r.options.Progress.IncrementRequests()
	}
	wg.Wait()

	return requestErr
}

// executeRaceRequest executes parallel requests for a template
func (r *Request) executeParallelHTTP(reqURL string, dynamicValues output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := r.newGenerator()

	// Workers that keeps enqueuing new requests
	maxWorkers := r.Threads
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	mutex := &sync.Mutex{}
	for {
		request, err := generator.Make(reqURL, dynamicValues, "")
		if err == io.EOF {
			break
		}
		if err != nil {
			r.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			r.options.RateLimiter.Take()

			previous := make(map[string]interface{})
			err := r.executeRequest(reqURL, httpRequest, previous, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(request)
		r.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
}

// executeTurboHTTP executes turbo http request for a URL
func (r *Request) executeTurboHTTP(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := r.newGenerator()

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
	if err != nil {
		return err
	}

	pipeOptions := rawhttp.DefaultPipelineOptions
	pipeOptions.Host = URL.Host
	pipeOptions.MaxConnections = 1
	if r.PipelineConcurrentConnections > 0 {
		pipeOptions.MaxConnections = r.PipelineConcurrentConnections
	}
	if r.PipelineRequestsPerConnection > 0 {
		pipeOptions.MaxPendingRequests = r.PipelineRequestsPerConnection
	}
	pipeclient := rawhttp.NewPipelineClient(pipeOptions)

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
		request, err := generator.Make(reqURL, dynamicValues, "")
		if err == io.EOF {
			break
		}
		if err != nil {
			r.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}
		request.pipelinedClient = pipeclient

		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			err := r.executeRequest(reqURL, httpRequest, previous, callback, 0)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(request)
		r.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
}

// ExecuteWithResults executes the final request on a URL
func (r *Request) ExecuteWithResults(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// verify if pipeline was requested
	if r.Pipeline {
		return r.executeTurboHTTP(reqURL, dynamicValues, previous, callback)
	}

	// verify if a basic race condition was requested
	if r.Race && r.RaceNumberRequests > 0 {
		return r.executeRaceRequest(reqURL, previous, callback)
	}

	// verify if parallel elaboration was requested
	if r.Threads > 0 {
		return r.executeParallelHTTP(reqURL, dynamicValues, callback)
	}

	generator := r.newGenerator()

	requestCount := 1
	var requestErr error
	for {
		hasInteractMarkers := interactsh.HasMatchers(r.CompiledOperators)

		var interactURL string
		if r.options.Interactsh != nil && hasInteractMarkers {
			interactURL = r.options.Interactsh.URL()
		}
		request, err := generator.Make(reqURL, dynamicValues, interactURL)
		if err == io.EOF {
			break
		}
		if err != nil {
			r.options.Progress.IncrementFailedRequestsBy(int64(generator.Total()))
			return err
		}

		var gotOutput bool
		r.options.RateLimiter.Take()
		err = r.executeRequest(reqURL, request, previous, func(event *output.InternalWrappedEvent) {
			// Add the extracts to the dynamic values if any.
			if event.OperatorsResult != nil {
				gotOutput = true
				dynamicValues = generators.MergeMaps(dynamicValues, event.OperatorsResult.DynamicValues)
			}
			if hasInteractMarkers && r.options.Interactsh != nil {
				r.options.Interactsh.RequestEvent(interactURL, &interactsh.RequestData{
					MakeResultFunc: r.MakeResultEvent,
					Event:          event,
					Operators:      r.CompiledOperators,
					MatchFunc:      r.Match,
					ExtractFunc:    r.Extract,
				})
			} else {
				callback(event)
			}
		}, requestCount)
		if err != nil {
			requestErr = multierr.Append(requestErr, err)
		}
		requestCount++
		r.options.Progress.IncrementRequests()

		if request.original.options.Options.StopAtFirstMatch && gotOutput {
			r.options.Progress.IncrementErrorsBy(int64(generator.Total()))
			break
		}
	}
	return requestErr
}

const drainReqSize = int64(8 * 1024)

// executeRequest executes the actual generated request and returns error if occurred
func (r *Request) executeRequest(reqURL string, request *generatedRequest, previous output.InternalEvent, callback protocols.OutputEventCallback, requestCount int) error {
	r.setCustomHeaders(request)

	var (
		resp          *http.Response
		fromcache     bool
		dumpedRequest []byte
		err           error
	)

	var formedURL string
	var hostname string
	timeStart := time.Now()
	if request.original.Pipeline {
		if request.rawRequest != nil {
			formedURL = request.rawRequest.FullURL
			if parsed, parseErr := url.Parse(formedURL); parseErr == nil {
				hostname = parsed.Host
			}
			resp, err = request.pipelinedClient.DoRaw(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)))
		} else if request.request != nil {
			resp, err = request.pipelinedClient.Dor(request.request)
		}
	} else if request.original.Unsafe && request.rawRequest != nil {
		formedURL = request.rawRequest.FullURL
		if parsed, parseErr := url.Parse(formedURL); parseErr == nil {
			hostname = parsed.Host
		}
		options := request.original.rawhttpClient.Options
		options.FollowRedirects = r.Redirects
		options.CustomRawBytes = request.rawRequest.UnsafeRawBytes
		resp, err = request.original.rawhttpClient.DoRawWithOptions(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)), options)
	} else {
		hostname = request.request.URL.Host
		formedURL = request.request.URL.String()
		// if nuclei-project is available check if the request was already sent previously
		if r.options.ProjectFile != nil {
			// if unavailable fail silently
			fromcache = true
			resp, err = r.options.ProjectFile.Get(dumpedRequest)
			if err != nil {
				fromcache = false
			}
		}
		if resp == nil {
			resp, err = r.httpClient.Do(request.request)
		}
	}

	// For race conditions we can't dump the request body at this point as it's already waiting the open-gate event, already handled with a similar code within the race function
	if !request.original.Race {
		dumpedRequest, err = dump(request, reqURL)
		if err != nil {
			return err
		}

		if r.options.Options.Debug || r.options.Options.DebugRequests {
			gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", r.options.TemplateID, reqURL)
			gologger.Print().Msgf("%s", string(dumpedRequest))
		}
	}

	if resp == nil {
		err = errors.New("no response got for request")
	}
	if err != nil {
		// rawhttp doesn't supports draining response bodies.
		if resp != nil && resp.Body != nil && request.rawRequest == nil {
			_, _ = io.CopyN(ioutil.Discard, resp.Body, drainReqSize)
			resp.Body.Close()
		}
		r.options.Output.Request(r.options.TemplateID, formedURL, "http", err)
		r.options.Progress.IncrementErrorsBy(1)
		return err
	}
	defer func() {
		_, _ = io.CopyN(ioutil.Discard, resp.Body, drainReqSize)
		resp.Body.Close()
	}()

	gologger.Verbose().Msgf("[%s] Sent HTTP request to %s", r.options.TemplateID, formedURL)
	r.options.Output.Request(r.options.TemplateID, formedURL, "http", err)

	duration := time.Since(timeStart)

	dumpedResponseHeaders, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return errors.Wrap(err, "could not dump http response")
	}

	var bodyReader io.Reader
	if r.MaxSize != 0 {
		bodyReader = io.LimitReader(resp.Body, int64(r.MaxSize))
	} else {
		bodyReader = resp.Body
	}
	data, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		// Ignore body read due to server misconfiguration errors
		if stringsutil.ContainsAny(err.Error(), "gzip: invalid header") {
			gologger.Warning().Msgf("[%s] Server sent an invalid gzip header and it was not possible to read the uncompressed body for %s: %s", r.options.TemplateID, formedURL, err.Error())
		} else if !stringsutil.ContainsAny(err.Error(), "unexpected EOF") { // ignore EOF error
			return errors.Wrap(err, "could not read http body")
		}
	}
	resp.Body.Close()

	redirectedResponse, err := dumpResponseWithRedirectChain(resp, data)
	if err != nil {
		return errors.Wrap(err, "could not read http response with redirect chain")
	}

	// net/http doesn't automatically decompress the response body if an
	// encoding has been specified by the user in the request so in case we have to
	// manually do it.
	dataOrig := data
	data, err = handleDecompression(resp, data)
	// in case of error use original data
	if err != nil {
		data = dataOrig
	}

	// Dump response - step 2 - replace gzip body with deflated one or with itself (NOP operation)
	dumpedResponseBuilder := &bytes.Buffer{}
	dumpedResponseBuilder.Write(dumpedResponseHeaders)
	dumpedResponseBuilder.Write(data)
	dumpedResponse := dumpedResponseBuilder.Bytes()
	redirectedResponse = bytes.ReplaceAll(redirectedResponse, dataOrig, data)

	// Dump response - step 2 - replace gzip body with deflated one or with itself (NOP operation)
	if r.options.Options.Debug || r.options.Options.DebugResponse {
		gologger.Info().Msgf("[%s] Dumped HTTP response for %s\n\n", r.options.TemplateID, formedURL)
		gologger.Print().Msgf("%s", string(redirectedResponse))
	}

	// if nuclei-project is enabled store the response if not previously done
	if r.options.ProjectFile != nil && !fromcache {
		err := r.options.ProjectFile.Set(dumpedRequest, resp, data)
		if err != nil {
			return errors.Wrap(err, "could not store in project file")
		}
	}

	matchedURL := reqURL
	if request.rawRequest != nil && request.rawRequest.FullURL != "" {
		matchedURL = request.rawRequest.FullURL
	}
	if request.request != nil {
		matchedURL = request.request.URL.String()
	}
	finalEvent := make(output.InternalEvent)

	outputEvent := r.responseToDSLMap(resp, reqURL, matchedURL, tostring.UnsafeToString(dumpedRequest), tostring.UnsafeToString(dumpedResponse), tostring.UnsafeToString(data), headersToString(resp.Header), duration, request.meta)
	if i := strings.LastIndex(hostname, ":"); i != -1 {
		hostname = hostname[:i]
	}
	outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)
	outputEvent["redirect-chain"] = tostring.UnsafeToString(redirectedResponse)
	for k, v := range previous {
		finalEvent[k] = v
	}
	for k, v := range outputEvent {
		finalEvent[k] = v
	}
	// Add to history the current request number metadata if asked by the user.
	if r.ReqCondition {
		for k, v := range outputEvent {
			key := fmt.Sprintf("%s_%d", k, requestCount)
			previous[key] = v
			finalEvent[key] = v
		}
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if r.CompiledOperators != nil {
		var ok bool
		event.OperatorsResult, ok = r.CompiledOperators.Execute(finalEvent, r.Match, r.Extract)
		if ok && event.OperatorsResult != nil {
			event.OperatorsResult.PayloadValues = request.meta
			event.Results = r.MakeResultEvent(event)
		}
		event.InternalEvent = outputEvent
	}
	callback(event)
	return nil
}

// setCustomHeaders sets the custom headers for generated request
func (r *Request) setCustomHeaders(req *generatedRequest) {
	for k, v := range r.customHeaders {
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
