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
	"strconv"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/pkg/protcols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/rawhttp"
	"github.com/remeh/sizedwaitgroup"
)

func (e *Request) ExecuteRaceRequest(reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.HasGenerator(reqURL) {
		return result
	}

	e.CreateGenerator(reqURL)

	// Workers that keeps enqueuing new requests
	maxWorkers := e.RaceNumberRequests
	swg := sizedwaitgroup.New(maxWorkers)
	for i := 0; i < e.RaceNumberRequests; i++ {
		swg.Add()
		// base request
		result.Lock()
		request, err := e.MakeHTTPRequest(reqURL, dynamicvalues, e.Current(reqURL))
		payloads, _ := e.GetPayloadsValues(reqURL)
		result.Unlock()
		// ignore the error due to the base request having null paylods
		if err == requests.ErrNoPayload {
			// pass through
		} else if err != nil {
			result.Error = err
		}
		go func(httpRequest *requests.HTTPRequest) {
			defer swg.Done()

			// If the request was built correctly then execute it
			err = e.handleHTTP(reqURL, httpRequest, dynamicvalues, result, payloads, "")
			if err != nil {
				result.Error = errors.Wrap(err, "could not handle http request")
			}
		}(request)
	}

	swg.Wait()

	return result
}

func (e *Request) ExecuteParallelHTTP(p *progress.Progress, reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.HasGenerator(reqURL) {
		return result
	}

	remaining := e.GetRequestCount()
	e.CreateGenerator(reqURL)

	// Workers that keeps enqueuing new requests
	maxWorkers := e.Threads
	swg := sizedwaitgroup.New(maxWorkers)
	for e.Next(reqURL) {
		result.Lock()
		request, err := e.MakeHTTPRequest(reqURL, dynamicvalues, e.Current(reqURL))
		payloads, _ := e.GetPayloadsValues(reqURL)
		result.Unlock()
		// ignore the error due to the base request having null paylods
		if err == requests.ErrNoPayload {
			// pass through
		} else if err != nil {
			result.Error = err
			p.Drop(remaining)
		} else {
			swg.Add()
			go func(httpRequest *requests.HTTPRequest) {
				defer swg.Done()

				e.ratelimiter.Take()

				// If the request was built correctly then execute it
				err = e.handleHTTP(reqURL, httpRequest, dynamicvalues, result, payloads, "")
				if err != nil {
					e.traceLog.Request(e.template.ID, reqURL, "http", err)
					result.Error = errors.Wrap(err, "could not handle http request")
					p.Drop(remaining)
				} else {
					e.traceLog.Request(e.template.ID, reqURL, "http", nil)
				}
			}(request)
		}
		p.Update()
		e.Increment(reqURL)
	}
	swg.Wait()

	return result
}

func (e *Request) ExecuteTurboHTTP(reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.HasGenerator(reqURL) {
		return result
	}

	e.CreateGenerator(reqURL)

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
	if err != nil {
		return result
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
	for e.Next(reqURL) {
		result.Lock()
		request, err := e.MakeHTTPRequest(reqURL, dynamicvalues, e.Current(reqURL))
		payloads, _ := e.GetPayloadsValues(reqURL)
		result.Unlock()
		// ignore the error due to the base request having null paylods
		if err == requests.ErrNoPayload {
			// pass through
		} else if err != nil {
			result.Error = err
		} else {
			swg.Add()
			go func(httpRequest *requests.HTTPRequest) {
				defer swg.Done()

				// HTTP pipelining ignores rate limit
				// If the request was built correctly then execute it
				request.Pipeline = true
				request.PipelineClient = pipeclient
				err = e.handleHTTP(reqURL, httpRequest, dynamicvalues, result, payloads, "")
				if err != nil {
					e.traceLog.Request(e.template.ID, reqURL, "http", err)
					result.Error = errors.Wrap(err, "could not handle http request")
				} else {
					e.traceLog.Request(e.template.ID, reqURL, "http", nil)
				}
				request.PipelineClient = nil
			}(request)
		}

		e.Increment(reqURL)
	}
	swg.Wait()
	return result
}

// ExecuteHTTP executes the HTTP request on a URL
func (e *Request) ExecuteHTTP(p *progress.Progress, reqURL string) *Result {
	// verify if pipeline was requested
	if e.Pipeline {
		return e.ExecuteTurboHTTP(reqURL)
	}

	// verify if a basic race condition was requested
	if e.Race && e.RaceNumberRequests > 0 {
		return e.ExecuteRaceRequest(reqURL)
	}

	// verify if parallel elaboration was requested
	if e.Threads > 0 {
		return e.ExecuteParallelHTTP(p, reqURL)
	}

	var requestNumber int

	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
		historyData: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.HasGenerator(reqURL) {
		return result
	}

	remaining := e.GetRequestCount()
	e.CreateGenerator(reqURL)

	for e.Next(reqURL) {
		requestNumber++
		result.Lock()
		httpRequest, err := e.MakeHTTPRequest(reqURL, dynamicvalues, e.Current(reqURL))
		payloads, _ := e.GetPayloadsValues(reqURL)
		result.Unlock()
		// ignore the error due to the base request having null paylods
		if err == requests.ErrNoPayload {
			// pass through
		} else if err != nil {
			result.Error = err
			p.Drop(remaining)
		} else {
			e.ratelimiter.Take()
			// If the request was built correctly then execute it
			format := "%s_" + strconv.Itoa(requestNumber)
			err = e.handleHTTP(reqURL, httpRequest, dynamicvalues, result, payloads, format)
			if err != nil {
				result.Error = errors.Wrap(err, "could not handle http request")
				p.Drop(remaining)
				e.traceLog.Request(e.template.ID, reqURL, "http", err)
			} else {
				e.traceLog.Request(e.template.ID, reqURL, "http", nil)
			}
		}
		p.Update()

		// Check if has to stop processing at first valid result
		if e.stopAtFirstMatch && result.GotResults {
			p.Drop(remaining)
			break
		}

		// move always forward with requests
		e.Increment(reqURL)
		remaining--
	}
	gologger.Verbosef("Sent for [%s] to %s\n", "http-request", e.template.ID, reqURL)
	return result
}

func (e *Request) handleHTTP(reqURL string, request *requests.HTTPRequest, dynamicvalues map[string]interface{}, result *Result, payloads map[string]interface{}, format string) error {
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

	if request.Pipeline {
		resp, err = request.PipelineClient.DoRaw(request.RawRequest.Method, reqURL, request.RawRequest.Path, requests.ExpandMapValues(request.RawRequest.Headers), ioutil.NopCloser(strings.NewReader(request.RawRequest.Data)))
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			e.traceLog.Request(e.template.ID, reqURL, "http", err)
			return err
		}
		e.traceLog.Request(e.template.ID, reqURL, "http", nil)
	} else if request.Unsafe {
		// rawhttp
		// burp uses "\r\n" as new line character
		request.RawRequest.Data = strings.ReplaceAll(request.RawRequest.Data, "\n", "\r\n")
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

	return nil
}
