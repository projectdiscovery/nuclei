package executer

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/bufwriter"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/internal/tracelog"
	"github.com/projectdiscovery/nuclei/v2/pkg/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	projetctfile "github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
	"golang.org/x/net/proxy"
)

const (
	two                   = 2
	ten                   = 10
	defaultMaxWorkers     = 150
	defaultMaxHistorydata = 150
)

// HTTPExecuter is client for performing HTTP requests
// for a template.
type HTTPExecuter struct {
	pf               *projetctfile.ProjectFile
	customHeaders    requests.CustomHeaders
	colorizer        colorizer.NucleiColorizer
	httpClient       *retryablehttp.Client
	rawHTTPClient    *rawhttp.Client
	template         *templates.Template
	bulkHTTPRequest  *requests.BulkHTTPRequest
	writer           *bufwriter.Writer
	CookieJar        *cookiejar.Jar
	traceLog         tracelog.Log
	decolorizer      *regexp.Regexp
	randomAgent      bool
	coloredOutput    bool
	debug            bool
	Results          bool
	jsonOutput       bool
	jsonRequest      bool
	noMeta           bool
	stopAtFirstMatch bool
	ratelimiter      ratelimit.Limiter
}

// HTTPOptions contains configuration options for the HTTP executer.
type HTTPOptions struct {
	RandomAgent      bool
	Debug            bool
	JSON             bool
	JSONRequests     bool
	NoMeta           bool
	CookieReuse      bool
	ColoredOutput    bool
	StopAtFirstMatch bool
	Timeout          int
	Retries          int
	ProxyURL         string
	ProxySocksURL    string
	Template         *templates.Template
	BulkHTTPRequest  *requests.BulkHTTPRequest
	Writer           *bufwriter.Writer
	CustomHeaders    requests.CustomHeaders
	CookieJar        *cookiejar.Jar
	Colorizer        *colorizer.NucleiColorizer
	Decolorizer      *regexp.Regexp
	TraceLog         tracelog.Log
	PF               *projetctfile.ProjectFile
	RateLimiter      ratelimit.Limiter
	Dialer           *fastdialer.Dialer
}

// NewHTTPExecuter creates a new HTTP executer from a template
// and a HTTP request query.
func NewHTTPExecuter(options *HTTPOptions) (*HTTPExecuter, error) {
	var (
		proxyURL *url.URL
		err      error
	)

	if options.ProxyURL != "" {
		proxyURL, err = url.Parse(options.ProxyURL)
	}

	if err != nil {
		return nil, err
	}

	// Create the HTTP Client
	client := makeHTTPClient(proxyURL, options)
	// nolint:bodyclose // false positive there is no body to close yet
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	if options.CookieJar != nil {
		client.HTTPClient.Jar = options.CookieJar
	} else if options.CookieReuse {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		client.HTTPClient.Jar = jar
	}

	// initiate raw http client
	rawClient := rawhttp.NewClient(rawhttp.DefaultOptions)

	executer := &HTTPExecuter{
		debug:            options.Debug,
		jsonOutput:       options.JSON,
		jsonRequest:      options.JSONRequests,
		noMeta:           options.NoMeta,
		httpClient:       client,
		rawHTTPClient:    rawClient,
		traceLog:         options.TraceLog,
		template:         options.Template,
		bulkHTTPRequest:  options.BulkHTTPRequest,
		writer:           options.Writer,
		randomAgent:      options.RandomAgent,
		customHeaders:    options.CustomHeaders,
		CookieJar:        options.CookieJar,
		coloredOutput:    options.ColoredOutput,
		colorizer:        *options.Colorizer,
		decolorizer:      options.Decolorizer,
		stopAtFirstMatch: options.StopAtFirstMatch,
		pf:               options.PF,
		ratelimiter:      options.RateLimiter,
	}

	return executer, nil
}

func (e *HTTPExecuter) ExecuteRaceRequest(reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.bulkHTTPRequest.HasGenerator(reqURL) {
		return result
	}

	e.bulkHTTPRequest.CreateGenerator(reqURL)

	// Workers that keeps enqueuing new requests
	maxWorkers := e.bulkHTTPRequest.RaceNumberRequests
	swg := sizedwaitgroup.New(maxWorkers)
	for i := 0; i < e.bulkHTTPRequest.RaceNumberRequests; i++ {
		swg.Add()
		// base request
		result.Lock()
		request, err := e.bulkHTTPRequest.MakeHTTPRequest(reqURL, dynamicvalues, e.bulkHTTPRequest.Current(reqURL))
		payloads, _ := e.bulkHTTPRequest.GetPayloadsValues(reqURL)
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

func (e *HTTPExecuter) ExecuteParallelHTTP(p *progress.Progress, reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.bulkHTTPRequest.HasGenerator(reqURL) {
		return result
	}

	remaining := e.bulkHTTPRequest.GetRequestCount()
	e.bulkHTTPRequest.CreateGenerator(reqURL)

	// Workers that keeps enqueuing new requests
	maxWorkers := e.bulkHTTPRequest.Threads
	swg := sizedwaitgroup.New(maxWorkers)
	for e.bulkHTTPRequest.Next(reqURL) {
		result.Lock()
		request, err := e.bulkHTTPRequest.MakeHTTPRequest(reqURL, dynamicvalues, e.bulkHTTPRequest.Current(reqURL))
		payloads, _ := e.bulkHTTPRequest.GetPayloadsValues(reqURL)
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
		e.bulkHTTPRequest.Increment(reqURL)
	}
	swg.Wait()

	return result
}

func (e *HTTPExecuter) ExecuteTurboHTTP(reqURL string) *Result {
	result := &Result{
		Matches:     make(map[string]interface{}),
		Extractions: make(map[string]interface{}),
	}

	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.bulkHTTPRequest.HasGenerator(reqURL) {
		return result
	}

	e.bulkHTTPRequest.CreateGenerator(reqURL)

	// need to extract the target from the url
	URL, err := url.Parse(reqURL)
	if err != nil {
		return result
	}

	pipeOptions := rawhttp.DefaultPipelineOptions
	pipeOptions.Host = URL.Host
	pipeOptions.MaxConnections = 1
	if e.bulkHTTPRequest.PipelineConcurrentConnections > 0 {
		pipeOptions.MaxConnections = e.bulkHTTPRequest.PipelineConcurrentConnections
	}
	if e.bulkHTTPRequest.PipelineRequestsPerConnection > 0 {
		pipeOptions.MaxPendingRequests = e.bulkHTTPRequest.PipelineRequestsPerConnection
	}
	pipeclient := rawhttp.NewPipelineClient(pipeOptions)

	// defaultMaxWorkers should be a sufficient value to keep queues always full
	maxWorkers := defaultMaxWorkers
	// in case the queue is bigger increase the workers
	if pipeOptions.MaxPendingRequests > maxWorkers {
		maxWorkers = pipeOptions.MaxPendingRequests
	}
	swg := sizedwaitgroup.New(maxWorkers)
	for e.bulkHTTPRequest.Next(reqURL) {
		result.Lock()
		request, err := e.bulkHTTPRequest.MakeHTTPRequest(reqURL, dynamicvalues, e.bulkHTTPRequest.Current(reqURL))
		payloads, _ := e.bulkHTTPRequest.GetPayloadsValues(reqURL)
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

		e.bulkHTTPRequest.Increment(reqURL)
	}
	swg.Wait()
	return result
}

// ExecuteHTTP executes the HTTP request on a URL
func (e *HTTPExecuter) ExecuteHTTP(p *progress.Progress, reqURL string) *Result {
	// verify if pipeline was requested
	if e.bulkHTTPRequest.Pipeline {
		return e.ExecuteTurboHTTP(reqURL)
	}

	// verify if a basic race condition was requested
	if e.bulkHTTPRequest.Race && e.bulkHTTPRequest.RaceNumberRequests > 0 {
		return e.ExecuteRaceRequest(reqURL)
	}

	// verify if parallel elaboration was requested
	if e.bulkHTTPRequest.Threads > 0 {
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
	if e.bulkHTTPRequest.HasGenerator(reqURL) {
		return result
	}

	remaining := e.bulkHTTPRequest.GetRequestCount()
	e.bulkHTTPRequest.CreateGenerator(reqURL)

	for e.bulkHTTPRequest.Next(reqURL) {
		requestNumber++
		result.Lock()
		httpRequest, err := e.bulkHTTPRequest.MakeHTTPRequest(reqURL, dynamicvalues, e.bulkHTTPRequest.Current(reqURL))
		payloads, _ := e.bulkHTTPRequest.GetPayloadsValues(reqURL)
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
		e.bulkHTTPRequest.Increment(reqURL)
		remaining--
	}
	gologger.Verbosef("Sent for [%s] to %s\n", "http-request", e.template.ID, reqURL)
	return result
}

func (e *HTTPExecuter) handleHTTP(reqURL string, request *requests.HTTPRequest, dynamicvalues map[string]interface{}, result *Result, payloads map[string]interface{}, format string) error {
	// Add User-Agent value randomly to the customHeaders slice if `random-agent` flag is given
	if e.randomAgent {
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

	matcherCondition := e.bulkHTTPRequest.GetMatchersCondition()
	for _, matcher := range e.bulkHTTPRequest.Matchers {
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

	for _, extractor := range e.bulkHTTPRequest.Extractors {
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

// Close closes the http executer for a template.
func (e *HTTPExecuter) Close() {}

// makeHTTPClient creates a http client
func makeHTTPClient(proxyURL *url.URL, options *HTTPOptions) *retryablehttp.Client {
	// Multiple Host
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	disableKeepAlives := true
	maxIdleConns := 0
	maxConnsPerHost := 0
	maxIdleConnsPerHost := -1

	if options.BulkHTTPRequest.Threads > 0 {
		// Single host
		retryablehttpOptions = retryablehttp.DefaultOptionsSingle
		disableKeepAlives = false
		maxIdleConnsPerHost = 500
		maxConnsPerHost = 500
	}

	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = options.Retries
	followRedirects := options.BulkHTTPRequest.Redirects
	maxRedirects := options.BulkHTTPRequest.MaxRedirects

	transport := &http.Transport{
		DialContext:         options.Dialer.Dial,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: disableKeepAlives,
	}

	// Attempts to overwrite the dial function with the socks proxied version
	if options.ProxySocksURL != "" {
		var proxyAuth *proxy.Auth

		socksURL, err := url.Parse(options.ProxySocksURL)

		if err == nil {
			proxyAuth = &proxy.Auth{}
			proxyAuth.User = socksURL.User.Username()
			proxyAuth.Password, _ = socksURL.User.Password()
		}

		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", socksURL.Hostname(), socksURL.Port()), proxyAuth, proxy.Direct)
		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})

		if err == nil {
			transport.DialContext = dc.DialContext
		}
	}

	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
		Timeout:       time.Duration(options.Timeout) * time.Second,
		CheckRedirect: makeCheckRedirectFunc(followRedirects, maxRedirects),
	}, retryablehttpOptions)
}

type checkRedirectFunc func(_ *http.Request, requests []*http.Request) error

func makeCheckRedirectFunc(followRedirects bool, maxRedirects int) checkRedirectFunc {
	return func(_ *http.Request, requests []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}

		if maxRedirects == 0 {
			if len(requests) > ten {
				return http.ErrUseLastResponse
			}

			return nil
		}

		if len(requests) > maxRedirects {
			return http.ErrUseLastResponse
		}

		return nil
	}
}

func (e *HTTPExecuter) setCustomHeaders(r *requests.HTTPRequest) {
	for _, customHeader := range e.customHeaders {
		// This should be pre-computed somewhere and done only once
		tokens := strings.SplitN(customHeader, ":", two)
		// if it's an invalid header skip it
		if len(tokens) < two {
			continue
		}

		headerName, headerValue := tokens[0], strings.Join(tokens[1:], "")
		if r.RawRequest != nil {
			// rawhttp
			r.RawRequest.Headers[headerName] = headerValue
		} else {
			// retryablehttp
			headerName = strings.TrimSpace(headerName)
			headerValue = strings.TrimSpace(headerValue)
			r.Request.Header[headerName] = []string{headerValue}
		}
	}
}

type Result struct {
	sync.Mutex
	GotResults  bool
	Meta        map[string]interface{}
	Matches     map[string]interface{}
	Extractions map[string]interface{}
	historyData map[string]interface{}
	Error       error
}
