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
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
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
			e.options.Progress.DecrementRequests(int64(generator.Remaining()))
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
			e.options.Progress.DecrementRequests(int64(generator.Remaining()))
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

// ExecuteHTTP executes the HTTP request on a URL
func (e *Request) ExecuteHTTP(reqURL string, dynamicValues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	// verify if pipeline was requested
	if e.Pipeline {
		return e.executeTurboHTTP(reqURL, dynamicValues)
	}

	// verify if a basic race condition was requested
	if e.Race && e.RaceNumberRequests > 0 {
		return e.executeRaceRequest(reqURL, dynamicValues)
	}

	// verify if parallel elaboration was requested
	if e.Threads > 0 {
		return e.executeParallelHTTP(reqURL, dynamicValues)
	}

	generator := e.newGenerator()

	var requestErr error
	var outputs []*output.InternalWrappedEvent
	for {
		request, err := generator.Make(reqURL, dynamicValues)
		if err == io.EOF {
			break
		}
		if err != nil {
			e.options.Progress.DecrementRequests(int64(generator.Remaining()))
			return nil, err
		}

		e.options.RateLimiter.Take()
		output, err := e.executeRequest(reqURL, request, dynamicValues)
		if err != nil {
			requestErr = multierr.Append(requestErr, err)
		} else {
			outputs = append(outputs, output...)
		}
		e.options.Progress.IncrementRequests()

		if request.original.options.Options.StopAtFirstMatch && len(output) > 0 {
			e.options.Progress.DecrementRequests(int64(generator.Remaining()))
			break
		}
	}
	return outputs, requestErr
}

// executeRequest executes the actual generated request and returns error if occured
func (e *Request) executeRequest(reqURL string, request *generatedRequest, dynamicvalues map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	// Add User-Agent value randomly to the customHeaders slice if `random-agent` flag is given
	if e.options.Options.RandomAgent {
		// nolint:errcheck // ignoring error
		e.customHeaders.Set("User-Agent: " + uarand.GetRandom())
	}

	e.setCustomHeaders(request)

	var (
		resp          *http.Response
		err           error
		dumpedRequest []byte
		fromcache     bool
	)

	if e.debug || e.pf != nil {
		dumpedRequest, err = requests.Dump(request, reqURL)
		if err != nil {
			return err
		}
	}

	if e.debug {
		gologger.Infof("Dumped HTTP request for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s", string(dumpedRequest))
	}

	timeStart := time.Now()

	if request.original.Pipeline {
		resp, err = request.PipelineClient.DoRaw(request.RawRequest.Method, reqURL, request.RawRequest.Path, requests.ExpandMapValues(request.RawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.RawRequest.Data)))
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			e.traceLog.Request(e.template.ID, reqURL, "http", err)
			return err
		}
		e.traceLog.Request(e.template.ID, reqURL, "http", nil)
	} else if request.original.Unsafe {
		// rawhttp
		// burp uses "\r\n" as new line character
		request.rawRequest.Data = strings.ReplaceAll(request.RawRequest.Data, "\n", "\r\n")
		options := e.rawHTTPClient.Options
		options.AutomaticContentLength = request.AutomaticContentLengthHeader
		options.AutomaticHostHeader = request.AutomaticHostHeader
		options.FollowRedirects = request.FollowRedirects
		resp, err = e.rawHTTPClient.DoRawWithOptions(request.RawRequest.Method, reqURL, request.RawRequest.Path, requests.ExpandMapValues(request.RawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.RawRequest.Data)), options)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			e.traceLog.Request(e.template.ID, reqURL, "http", err)
			return err
		}
		e.traceLog.Request(e.template.ID, reqURL, "http", nil)
	} else {
		// if nuclei-project is available check if the request was already sent previously
		if e.pf != nil {
			// if unavailable fail silently
			fromcache = true
			// nolint:bodyclose // false positive the response is generated at runtime
			resp, err = e.pf.Get(dumpedRequest)
			if err != nil {
				fromcache = false
			}
		}

		// retryablehttp
		if resp == nil {
			resp, err = e.httpClient.Do(request.Request)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				e.traceLog.Request(e.template.ID, reqURL, "http", err)
				return err
			}
			e.traceLog.Request(e.template.ID, reqURL, "http", nil)
		}
	}

	duration := time.Since(timeStart)

	// Dump response - Step 1 - Decompression not yet handled
	var dumpedResponse []byte
	if e.debug {
		var dumpErr error
		dumpedResponse, dumpErr = httputil.DumpResponse(resp, true)
		if dumpErr != nil {
			return errors.Wrap(dumpErr, "could not dump http response")
		}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_, copyErr := io.Copy(ioutil.Discard, resp.Body)
		if copyErr != nil {
			resp.Body.Close()
			return copyErr
		}

		resp.Body.Close()

		return errors.Wrap(err, "could not read http body")
	}

	resp.Body.Close()

	// net/http doesn't automatically decompress the response body if an encoding has been specified by the user in the request
	// so in case we have to manually do it
	dataOrig := data
	data, err = requests.HandleDecompression(request, data)
	if err != nil {
		return errors.Wrap(err, "could not decompress http body")
	}

	// Dump response - step 2 - replace gzip body with deflated one or with itself (NOP operation)
	if e.debug {
		dumpedResponse = bytes.ReplaceAll(dumpedResponse, dataOrig, data)
		gologger.Infof("Dumped HTTP response for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", string(dumpedResponse))
	}

	// if nuclei-project is enabled store the response if not previously done
	if e.pf != nil && !fromcache {
		err := e.pf.Set(dumpedRequest, resp, data)
		if err != nil {
			return errors.Wrap(err, "could not store in project file")
		}
	}

	// Convert response body from []byte to string with zero copy
	body := unsafeToString(data)

	headers := headersToString(resp.Header)

	var matchData map[string]interface{}
	if payloads != nil {
		matchData = generators.MergeMaps(result.historyData, payloads)
	}

	// store for internal purposes the DSL matcher data
	// hardcode stopping storing data after defaultMaxHistorydata items
	if len(result.historyData) < defaultMaxHistorydata {
		result.Lock()
		// update history data with current reqURL and hostname
		result.historyData["reqURL"] = reqURL
		if parsed, err := url.Parse(reqURL); err == nil {
			result.historyData["Hostname"] = parsed.Host
		}
		result.historyData = generators.MergeMaps(result.historyData, matchers.HTTPToMap(resp, body, headers, duration, format))
		if payloads == nil {
			// merge them to history data
			result.historyData = generators.MergeMaps(result.historyData, payloads)
		}
		result.historyData = generators.MergeMaps(result.historyData, dynamicvalues)

		// complement match data with new one if necessary
		matchData = generators.MergeMaps(matchData, result.historyData)
		result.Unlock()
	}

	matcherCondition := e.GetMatchersCondition()
	for _, matcher := range e.Matchers {
		// Check if the matcher matched
		if !matcher.Match(resp, body, headers, duration, matchData) {
			// If the condition is AND we haven't matched, try next request.
			if matcherCondition == matchers.ANDCondition {
				return nil
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition {
				result.Lock()
				result.Matches[matcher.Name] = nil
				// probably redundant but ensures we snapshot current payload values when matchers are valid
				result.Meta = request.Meta
				result.GotResults = true
				result.Unlock()
				e.writeOutputHTTP(request, resp, body, matcher, nil, request.Meta, reqURL)
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults, outputExtractorResults []string

	for _, extractor := range e.Extractors {
		for match := range extractor.Extract(resp, body, headers) {
			if _, ok := dynamicvalues[extractor.Name]; !ok {
				dynamicvalues[extractor.Name] = match
			}

			extractorResults = append(extractorResults, match)

			if !extractor.Internal {
				outputExtractorResults = append(outputExtractorResults, match)
			}
		}
		// probably redundant but ensures we snapshot current payload values when extractors are valid
		result.Lock()
		result.Meta = request.Meta
		result.Extractions[extractor.Name] = extractorResults
		result.Unlock()
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(outputExtractorResults) > 0 || matcherCondition == matchers.ANDCondition {
		e.writeOutputHTTP(request, resp, body, nil, outputExtractorResults, request.Meta, reqURL)
		result.Lock()
		result.GotResults = true
		result.Unlock()
	}

	gologger.Verbosef("Sent for [%s] to %s\n", "http-request", e.template.ID, reqURL)
	return nil
}
