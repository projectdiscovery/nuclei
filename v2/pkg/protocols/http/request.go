package http

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/valyala/fasttemplate"
	"go.uber.org/multierr"
)

const defaultMaxWorkers = 150

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeRaceRequest(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := e.newGenerator()

	maxWorkers := e.RaceNumberRequests
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	mutex := &sync.Mutex{}

	request, err := generator.Make(reqURL, nil)
	if err != nil {
		return err
	}
	for i := 0; i < e.RaceNumberRequests; i++ {
		swg.Add()
		go func(httpRequest *generatedRequest) {
			_, err := e.executeRequest(reqURL, httpRequest, dynamicValues, previous, callback)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
			swg.Done()
		}(request)
	}
	swg.Wait()
	return requestErr
}

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeParallelHTTP(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := e.newGenerator()

	// Workers that keeps enqueuing new requests
	maxWorkers := e.Threads
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	mutex := &sync.Mutex{}
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			e.options.Progress.DecrementRequests(int64(generator.Total()))
			return err
		}
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			e.options.RateLimiter.Take()
			_, err := e.executeRequest(reqURL, httpRequest, dynamicValues, previous, callback)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(request)
		e.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
}

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeTurboHTTP(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	generator := e.newGenerator()

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
	if err != nil {
		return err
	}

	pipeOptions := rawhttp.DefaultPipelineOptions
	pipeOptions.Host = URL.Host
	pipeOptions.MaxConnections = 1
	if e.PipelineConcurrentConnections > 0 {
		pipeOptions.MaxConnections = e.PipelineConcurrentConnections
	}
	if e.PipelineRequestsPerConnection > 0 {
		pipeOptions.MaxPendingRequests = e.PipelineRequestsPerConnection
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
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			e.options.Progress.DecrementRequests(int64(generator.Total()))
			return err
		}
		request.pipelinedClient = pipeclient

		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			_, err := e.executeRequest(reqURL, httpRequest, dynamicValues, previous, callback)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			}
			mutex.Unlock()
		}(request)
		e.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return requestErr
}

var interactshURLMarker = "{{interactsh-url}}"

// executeFuzzing executes fuzzing request for an input
func (r *Request) executeFuzzing(data string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	req := &fuzzing.NormalizedRequest{}

	if strings.HasPrefix(data, "{\"") {
		if err := jsoniter.NewDecoder(strings.NewReader(data)).Decode(req); err != nil {
			gologger.Warning().Msgf("Could not parse normalized request: %s\n", err)
			return err
		}
	} else {
		req.Method = "GET"
		parsed, err := url.Parse(data)
		if err != nil {
			gologger.Warning().Msgf("Could not parse url for fuzzing: %s\n", err)
			return err
		}
		req.Host = parsed.Host
		req.Path = parsed.Path
		req.Scheme = parsed.Scheme
		req.QueryValues = parsed.Query()
		req.Headers = make(http.Header, 3)
		req.Headers.Set("User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")
		req.Headers.Set("Accept", "*/*")
		req.Headers.Set("Accept-Language", "en")
	}

	interactshURL := ""
	if r.options.InteractshClient != nil {
		interactshURL = r.options.InteractshClient.URL()
	}
	analyzer := &fuzzing.AnalyzerOptions{
		BodyType:    r.CompiledAnalyzer.BodyType,
		MaxDepth:    r.CompiledAnalyzer.MaxDepth,
		Parts:       r.CompiledAnalyzer.Parts,
		PartsConfig: r.CompiledAnalyzer.PartsConfig,
	}
	for _, item := range r.CompiledAnalyzer.Append {
		analyzer.Append = append(analyzer.Append, fasttemplate.ExecuteStringStd(item, "{{", "}}", map[string]interface{}{"interactsh-url": interactshURL}))
	}
	for _, item := range r.CompiledAnalyzer.Replace {
		analyzer.Replace = append(analyzer.Replace, fasttemplate.ExecuteStringStd(item, "{{", "}}", map[string]interface{}{"interactsh-url": interactshURL}))
	}
	analyzer.BodyTemplate = fasttemplate.ExecuteStringStd(r.CompiledAnalyzer.BodyTemplate, "{{", "}}", map[string]interface{}{"interactsh-url": interactshURL})

	err := fuzzing.AnalyzeRequest(req, analyzer, func(req *http.Request) bool {
		retryable, err := retryablehttp.FromRequest(req)
		if err != nil {
			gologger.Warning().Msgf("Could not convert request to retryable for fuzzing: %s\n", err)
			return true
		}
		results, err := r.executeRequest(retryable.URL.String(), &generatedRequest{request: retryable, original: r}, dynamicValues, previous, func(result *output.InternalWrappedEvent) {
			if r.options.InteractshClient != nil {
				r.options.InteractshClient.RequestEvent(interactshURL, result, r.MakeResultEvent)
			}
			callback(result)
		})
		if err != nil {
			gologger.Warning().Msgf("Could not execute request for fuzzing: %s\n", err)
			return true
		}
		if results && r.options.Options.StopAtFirstMatch { // exit if we matched and user wants us to
			return false
		}
		return true
	})
	if err != nil {
		gologger.Warning().Msgf("Could not analyze request for fuzzing: %s\n", err)
		return nil
	}
	return nil
}

// ExecuteWithResults executes the final request on a URL
func (r *Request) ExecuteWithResults(reqURL string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// verify if fuzzing was asked by the user
	if len(r.Append) > 0 || len(r.Replace) > 0 || len(r.BodyTemplate) > 0 {
		return r.executeFuzzing(reqURL, dynamicValues, previous, callback)
	}

	// verify if pipeline was requested
	if r.Pipeline {
		return r.executeTurboHTTP(reqURL, dynamicValues, previous, callback)
	}

	// verify if a basic race condition was requested
	if r.Race && r.RaceNumberRequests > 0 {
		return r.executeRaceRequest(reqURL, dynamicValues, previous, callback)
	}

	// verify if parallel elaboration was requested
	if r.Threads > 0 {
		return r.executeParallelHTTP(reqURL, dynamicValues, previous, callback)
	}

	generator := r.newGenerator()

	var requestErr error
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			r.options.Progress.DecrementRequests(int64(generator.Total()))
			return err
		}

		var gotOutput bool
		r.options.RateLimiter.Take()
		_, err = r.executeRequest(reqURL, request, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			// Add the extracts to the dynamic values if any.
			if event.OperatorsResult != nil {
				gotOutput = true
				dynamicValues = generators.MergeMaps(dynamicValues, event.OperatorsResult.DynamicValues)
			}
			callback(event)
		})
		if err != nil {
			requestErr = multierr.Append(requestErr, err)
		}
		r.options.Progress.IncrementRequests()

		if request.original.options.Options.StopAtFirstMatch && gotOutput {
			r.options.Progress.DecrementRequests(int64(generator.Total()))
			break
		}
	}
	return requestErr
}

// executeRequest executes the actual generated request and returns error if occured
func (r *Request) executeRequest(reqURL string, request *generatedRequest, dynamicvalues, previous output.InternalEvent, callback protocols.OutputEventCallback) (bool, error) {
	// Add User-Agent value randomly to the customHeaders slice if `random-agent` flag is given
	if r.options.Options.RandomAgent {
		builder := &strings.Builder{}
		builder.WriteString("User-Agent: ")
		builder.WriteString(uarand.GetRandom())
		r.customHeaders = append(r.customHeaders, builder.String())
	}
	r.setCustomHeaders(request)

	var (
		resp          *http.Response
		err           error
		dumpedRequest []byte
		fromcache     bool
	)
	if r.options.Options.Debug || r.options.ProjectFile != nil || r.options.Options.DebugRequests {
		dumpedRequest, err = dump(request, reqURL)
		if err != nil {
			return false, err
		}
	}
	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", r.options.TemplateID, reqURL)
		gologger.Print().Msgf("%s", string(dumpedRequest))
	}

	var formedURL string
	var hostname string
	timeStart := time.Now()
	if request.original.Pipeline {
		formedURL = request.rawRequest.FullURL
		if parsed, err := url.Parse(formedURL); err == nil {
			hostname = parsed.Hostname()
		}
		resp, err = request.pipelinedClient.DoRaw(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)))
	} else if request.original.Unsafe {
		formedURL = request.rawRequest.FullURL
		if parsed, err := url.Parse(formedURL); err == nil {
			hostname = parsed.Hostname()
		}
		request.rawRequest.Data = strings.ReplaceAll(request.rawRequest.Data, "\n", "\r\n")
		options := request.original.rawhttpClient.Options
		options.AutomaticContentLength = !r.DisableAutoContentLength
		options.AutomaticHostHeader = !r.DisableAutoHostname
		options.FollowRedirects = r.Redirects
		resp, err = request.original.rawhttpClient.DoRawWithOptions(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)), options)
	} else {
		hostname = request.request.URL.Hostname()
		formedURL = request.request.URL.String()
		// if nuclei-project is available check if the request was already sent previously
		if r.options.ProjectFile != nil {
			// if unavailable fail silently
			fromcache = true
			// nolint:bodyclose // false positive the response is generated at runtime
			resp, err = r.options.ProjectFile.Get(dumpedRequest)
			if err != nil {
				fromcache = false
			}
		}
		if resp == nil {
			resp, err = r.httpClient.Do(request.request)
		}
	}
	if err != nil {
		// rawhttp doesn't supports draining response bodies.
		if resp != nil && resp.Body != nil && request.rawRequest == nil {
			_, _ = io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		r.options.Output.Request(r.options.TemplateID, reqURL, "http", err)
		r.options.Progress.DecrementRequests(1)
		return false, err
	}
	gologger.Verbose().Msgf("[%s] Sent HTTP request to %s", r.options.TemplateID, formedURL)
	r.options.Output.Request(r.options.TemplateID, reqURL, "http", err)

	duration := time.Since(timeStart)
	// Dump response - Step 1 - Decompression not yet handled
	var dumpedResponse []byte
	if r.options.Options.Debug || r.options.Options.DebugResponse {
		var dumpErr error
		dumpedResponse, dumpErr = httputil.DumpResponse(resp, true)
		if dumpErr != nil {
			return false, errors.Wrap(dumpErr, "could not dump http response")
		}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return false, errors.Wrap(err, "could not read http body")
	}
	resp.Body.Close()

	// net/http doesn't automatically decompress the response body if an
	// encoding has been specified by the user in the request so in case we have to
	// manually do it.
	dataOrig := data
	data, err = handleDecompression(request, data)
	if err != nil {
		return false, errors.Wrap(err, "could not decompress http body")
	}

	// Dump response - step 2 - replace gzip body with deflated one or with itself (NOP operation)
	if r.options.Options.Debug || r.options.Options.DebugResponse {
		dumpedResponse = bytes.ReplaceAll(dumpedResponse, dataOrig, data)
		gologger.Info().Msgf("[%s] Dumped HTTP response for %s\n\n", r.options.TemplateID, formedURL)
		gologger.Print().Msgf("%s", string(dumpedResponse))
	}

	// if nuclei-project is enabled store the response if not previously done
	if r.options.ProjectFile != nil && !fromcache {
		err := r.options.ProjectFile.Set(dumpedRequest, resp, data)
		if err != nil {
			return false, errors.Wrap(err, "could not store in project file")
		}
	}

	var matchedURL string
	if request.rawRequest != nil {
		matchedURL = request.rawRequest.FullURL
	}
	if request.request != nil {
		matchedURL = request.request.URL.String()
	}
	outputEvent := r.responseToDSLMap(resp, reqURL, matchedURL, tostring.UnsafeToString(dumpedRequest), tostring.UnsafeToString(dumpedResponse), tostring.UnsafeToString(data), headersToString(resp.Header), duration, request.meta)
	outputEvent["ip"] = httpclientpool.Dialer.GetDialedIP(hostname)
	for k, v := range previous {
		outputEvent[k] = v
	}

	var gotResult bool
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if r.CompiledOperators != nil {
		var ok bool
		event.OperatorsResult, ok = r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
		if ok && event.OperatorsResult != nil {
			gotResult = true
			event.OperatorsResult.PayloadValues = request.meta
			event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)
	return gotResult, nil
}

const two = 2

// setCustomHeaders sets the custom headers for generated request
func (e *Request) setCustomHeaders(r *generatedRequest) {
	for _, customHeader := range e.customHeaders {
		if customHeader == "" {
			continue
		}

		// This should be pre-computed somewhere and done only once
		tokens := strings.SplitN(customHeader, ":", two)
		// if it's an invalid header skip it
		if len(tokens) < 2 {
			continue
		}

		headerName, headerValue := tokens[0], strings.Join(tokens[1:], "")
		if r.rawRequest != nil {
			r.rawRequest.Headers[headerName] = headerValue
		} else {
			r.request.Header.Set(strings.TrimSpace(headerName), strings.TrimSpace(headerValue))
		}
	}
}
