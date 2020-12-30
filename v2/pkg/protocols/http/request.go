package http

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/rawhttp"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/multierr"
)

const defaultMaxWorkers = 150

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeRaceRequest(reqURL string, dynamicValues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	generator := e.newGenerator()

	maxWorkers := e.RaceNumberRequests
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	var mutex *sync.Mutex
	var outputs []*output.InternalWrappedEvent
	for i := 0; i < e.RaceNumberRequests; i++ {
		request, err := generator.Make(reqURL, nil)
		if err != nil {
			break
		}

		swg.Add()
		go func(httpRequest *generatedRequest) {
			output, err := e.executeRequest(reqURL, httpRequest, dynamicValues)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			} else {
				outputs = append(outputs, output...)
			}
			mutex.Unlock()
			swg.Done()
		}(request)
	}
	swg.Wait()
	return outputs, requestErr
}

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeParallelHTTP(reqURL string, dynamicValues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	generator := e.newGenerator()

	// Workers that keeps enqueuing new requests
	maxWorkers := e.Threads
	swg := sizedwaitgroup.New(maxWorkers)

	var requestErr error
	var mutex *sync.Mutex
	var outputs []*output.InternalWrappedEvent
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			e.options.Progress.DecrementRequests(int64(generator.Total()))
			return nil, err
		}
		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			e.options.RateLimiter.Take()
			output, err := e.executeRequest(reqURL, httpRequest, dynamicValues)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			} else {
				outputs = append(outputs, output...)
			}
			mutex.Unlock()
		}(request)
		e.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return outputs, requestErr
}

// executeRaceRequest executes race condition request for a URL
func (e *Request) executeTurboHTTP(reqURL string, dynamicValues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	generator := e.newGenerator()

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
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
	var mutex *sync.Mutex
	var outputs []*output.InternalWrappedEvent
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			e.options.Progress.DecrementRequests(int64(generator.Total()))
			return nil, err
		}
		request.pipelinedClient = pipeclient

		swg.Add()
		go func(httpRequest *generatedRequest) {
			defer swg.Done()

			output, err := e.executeRequest(reqURL, httpRequest, dynamicValues)
			mutex.Lock()
			if err != nil {
				requestErr = multierr.Append(requestErr, err)
			} else {
				outputs = append(outputs, output...)
			}
			mutex.Unlock()
		}(request)
		e.options.Progress.IncrementRequests()
	}
	swg.Wait()
	return outputs, requestErr
}

// ExecuteWithResults executes the final request on a URL
func (r *Request) ExecuteWithResults(reqURL string, dynamicValues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	// verify if pipeline was requested
	if r.Pipeline {
		return r.executeTurboHTTP(reqURL, dynamicValues)
	}

	// verify if a basic race condition was requested
	if r.Race && r.RaceNumberRequests > 0 {
		return r.executeRaceRequest(reqURL, dynamicValues)
	}

	// verify if parallel elaboration was requested
	if r.Threads > 0 {
		return r.executeParallelHTTP(reqURL, dynamicValues)
	}

	generator := r.newGenerator()

	var requestErr error
	var outputs []*output.InternalWrappedEvent
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			r.options.Progress.DecrementRequests(int64(generator.Total()))
			return nil, err
		}

		r.options.RateLimiter.Take()
		output, err := r.executeRequest(reqURL, request, dynamicValues)
		if err != nil {
			requestErr = multierr.Append(requestErr, err)
		} else {
			outputs = append(outputs, output...)
		}
		r.options.Progress.IncrementRequests()

		if request.original.options.Options.StopAtFirstMatch && len(output) > 0 {
			r.options.Progress.DecrementRequests(int64(generator.Total()))
			break
		}
	}
	return outputs, requestErr
}

// executeRequest executes the actual generated request and returns error if occured
func (r *Request) executeRequest(reqURL string, request *generatedRequest, dynamicvalues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	// Add User-Agent value randomly to the customHeaders slice if `random-agent` flag is given
	if r.options.Options.RandomAgent {
		builder := &strings.Builder{}
		builder.WriteString("User-Agent: ")
		builder.WriteString(uarand.GetRandom())
		r.customHeaders.Set(builder.String())
	}
	r.setCustomHeaders(request)

	var (
		resp          *http.Response
		err           error
		dumpedRequest []byte
		fromcache     bool
	)
	if r.options.Options.Debug || r.options.ProjectFile != nil {
		dumpedRequest, err = dump(request, reqURL)
		if err != nil {
			return nil, err
		}
	}
	if r.options.Options.Debug {
		gologger.Info().Msgf("[%s] Dumped HTTP request for %s\n\n", r.options.TemplateID, reqURL)
		fmt.Fprintf(os.Stderr, "%s", string(dumpedRequest))
	}

	timeStart := time.Now()
	if request.original.Pipeline {
		resp, err = request.pipelinedClient.DoRaw(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)))
	} else if request.original.Unsafe {
		// rawhttp
		// burp uses "\r\n" as new line character
		request.rawRequest.Data = strings.ReplaceAll(request.rawRequest.Data, "\n", "\r\n")
		options := request.original.rawhttpClient.Options
		options.AutomaticContentLength = !r.DisableAutoContentLength
		options.AutomaticHostHeader = !r.DisableAutoHostname
		options.FollowRedirects = r.Redirects
		resp, err = request.original.rawhttpClient.DoRawWithOptions(request.rawRequest.Method, reqURL, request.rawRequest.Path, generators.ExpandMapValues(request.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.rawRequest.Data)), options)
	} else {
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
		if resp != nil {
			_, _ = io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		r.options.Output.Request(r.options.TemplateID, reqURL, "http", err)
		r.options.Progress.DecrementRequests(1)
		return nil, err
	}
	gologger.Verbose().Msgf("Sent request to %s", reqURL)
	r.options.Output.Request(r.options.TemplateID, reqURL, "http", err)

	duration := time.Since(timeStart)
	// Dump response - Step 1 - Decompression not yet handled
	var dumpedResponse []byte
	if r.options.Options.Debug {
		var dumpErr error
		dumpedResponse, dumpErr = httputil.DumpResponse(resp, true)
		if dumpErr != nil {
			return nil, errors.Wrap(dumpErr, "could not dump http response")
		}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return nil, errors.Wrap(err, "could not read http body")
	}
	resp.Body.Close()

	// net/http doesn't automatically decompress the response body if an
	// encoding has been specified by the user in the request so in case we have to
	// manually do it.
	dataOrig := data
	data, err = handleDecompression(request, data)
	if err != nil {
		return nil, errors.Wrap(err, "could not decompress http body")
	}

	// Dump response - step 2 - replace gzip body with deflated one or with itself (NOP operation)
	if r.options.Options.Debug {
		dumpedResponse = bytes.ReplaceAll(dumpedResponse, dataOrig, data)
		gologger.Info().Msgf("[%s] Dumped HTTP response for %s\n\n", r.options.TemplateID, reqURL)
		fmt.Fprintf(os.Stderr, "%s\n", string(dumpedResponse))
	}

	// if nuclei-project is enabled store the response if not previously done
	if r.options.ProjectFile != nil && !fromcache {
		err := r.options.ProjectFile.Set(dumpedRequest, resp, data)
		if err != nil {
			return nil, errors.Wrap(err, "could not store in project file")
		}
	}

	// store for internal purposes the DSL matcher data
	// hardcode stopping storing data after defaultMaxHistorydata items
	//if len(result.historyData) < defaultMaxHistorydata {
	//	result.Lock()
	//	// update history data with current reqURL and hostname
	//	result.historyData["reqURL"] = reqURL
	//	if parsed, err := url.Parse(reqURL); err == nil {
	//		result.historyData["Hostname"] = parsed.Host
	//	}
	//	result.historyData = generators.MergeMaps(result.historyData, matchers.HTTPToMap(resp, body, headers, duration, format))
	//	if payloads == nil {
	//		// merge them to history data
	//		result.historyData = generators.MergeMaps(result.historyData, payloads)
	//	}
	//	result.historyData = generators.MergeMaps(result.historyData, dynamicvalues)
	//
	//	// complement match data with new one if necessary
	//	matchData = generators.MergeMaps(matchData, result.historyData)
	//	result.Unlock()
	//}
	var matchedURL string
	if request.rawRequest != nil {
		matchedURL = request.rawRequest.FullURL
	}
	if request.request != nil {
		matchedURL = request.request.URL.String()
	}
	ouputEvent := r.responseToDSLMap(resp, reqURL, matchedURL, unsafeToString(dumpedRequest), unsafeToString(dumpedResponse), unsafeToString(data), headersToString(resp.Header), duration, request.meta)

	event := []*output.InternalWrappedEvent{{InternalEvent: ouputEvent}}
	if r.CompiledOperators != nil {
		result, ok := r.Operators.Execute(ouputEvent, r.Match, r.Extract)
		if !ok {
			return nil, nil
		}
		result.PayloadValues = request.meta
		event[0].OperatorsResult = result
	}
	return event, nil
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
