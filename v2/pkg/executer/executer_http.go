package executer

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/proxy"
)

// HTTPExecuter is client for performing HTTP requests
// for a template.
type HTTPExecuter struct {
	debug           bool
	Results         bool
	jsonOutput      bool
	jsonRequest     bool
	httpClient      *retryablehttp.Client
	template        *templates.Template
	bulkHttpRequest *requests.BulkHTTPRequest
	writer          *bufio.Writer
	outputMutex     *sync.Mutex
	customHeaders   requests.CustomHeaders
	CookieJar       *cookiejar.Jar
}

// HTTPOptions contains configuration options for the HTTP executer.
type HTTPOptions struct {
	Template        *templates.Template
	BulkHttpRequest *requests.BulkHTTPRequest
	Writer          *bufio.Writer
	Timeout         int
	Retries         int
	ProxyURL        string
	ProxySocksURL   string
	Debug           bool
	JSON            bool
	JSONRequests    bool
	CustomHeaders   requests.CustomHeaders
	CookieReuse     bool
	CookieJar       *cookiejar.Jar
}

// NewHTTPExecuter creates a new HTTP executer from a template
// and a HTTP request query.
func NewHTTPExecuter(options *HTTPOptions) (*HTTPExecuter, error) {
	var proxyURL *url.URL
	var err error

	if options.ProxyURL != "" {
		proxyURL, err = url.Parse(options.ProxyURL)
	}
	if err != nil {
		return nil, err
	}

	// Create the HTTP Client
	client := makeHTTPClient(proxyURL, options)
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

	executer := &HTTPExecuter{
		debug:           options.Debug,
		jsonOutput:      options.JSON,
		jsonRequest:     options.JSONRequests,
		httpClient:      client,
		template:        options.Template,
		bulkHttpRequest: options.BulkHttpRequest,
		outputMutex:     &sync.Mutex{},
		writer:          options.Writer,
		customHeaders:   options.CustomHeaders,
		CookieJar:       options.CookieJar,
	}

	return executer, nil
}

// ExecuteHTTP executes the HTTP request on a URL
func (e *HTTPExecuter) ExecuteHTTP(URL string) (result Result) {
	result.Matches = make(map[string]interface{})
	result.Extractions = make(map[string]interface{})
	dynamicvalues := make(map[string]interface{})

	// verify if the URL is already being processed
	if e.bulkHttpRequest.HasGenerator(URL) {
		return
	}

	e.bulkHttpRequest.CreateGenerator(URL)
	for e.bulkHttpRequest.Next(URL) && !result.Done {
		httpRequest, err := e.bulkHttpRequest.MakeHTTPRequest(URL, dynamicvalues, e.bulkHttpRequest.Current(URL))
		if err != nil {
			result.Error = errors.Wrap(err, "could not make http request")
			return
		}

		err = e.handleHTTP(URL, httpRequest, dynamicvalues, &result)
		if err != nil {
			result.Error = errors.Wrap(err, "could not make http request")
			return
		}

		e.bulkHttpRequest.Increment(URL)
	}

	gologger.Verbosef("Sent HTTP request to %s\n", "http-request", URL)

	return
}

func (e *HTTPExecuter) handleHTTP(URL string, request *requests.HttpRequest, dynamicvalues map[string]interface{}, result *Result) error {
	e.setCustomHeaders(request)
	req := request.Request

	if e.debug {
		gologger.Infof("Dumped HTTP request for %s (%s)\n\n", URL, e.template.ID)
		dumpedRequest, err := httputil.DumpRequest(req.Request, true)
		if err != nil {
			return errors.Wrap(err, "could not make http request")
		}
		fmt.Fprintf(os.Stderr, "%s", string(dumpedRequest))
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return errors.Wrap(err, "Could not do request")
	}

	if e.debug {
		gologger.Infof("Dumped HTTP response for %s (%s)\n\n", URL, e.template.ID)
		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return errors.Wrap(err, "could not dump http response")
		}
		fmt.Fprintf(os.Stderr, "%s\n", string(dumpedResponse))
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return errors.Wrap(err, "could not read http body")
	}
	resp.Body.Close()

	// net/http doesn't automatically decompress the response body if an encoding has been specified by the user in the request
	// so in case we have to manually do it
	data, err = requests.HandleDecompression(req, data)
	if err != nil {
		return errors.Wrap(err, "could not decompress http body")
	}

	// Convert response body from []byte to string with zero copy
	body := unsafeToString(data)

	headers := headersToString(resp.Header)
	matcherCondition := e.bulkHttpRequest.GetMatchersCondition()
	for _, matcher := range e.bulkHttpRequest.Matchers {
		// Check if the matcher matched
		if !matcher.Match(resp, body, headers) {
			// If the condition is AND we haven't matched, try next request.
			if matcherCondition == matchers.ANDCondition {
				return nil
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition {
				result.Matches[matcher.Name] = nil
				// probably redundant but ensures we snapshot current payload values when matchers are valid
				result.Meta = request.Meta
				e.writeOutputHTTP(request, resp, body, matcher, nil)
				result.GotResults = true
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults, outputExtractorResults []string
	for _, extractor := range e.bulkHttpRequest.Extractors {
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
		result.Meta = request.Meta
		result.Extractions[extractor.Name] = extractorResults
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(outputExtractorResults) > 0 || matcherCondition == matchers.ANDCondition {
		e.writeOutputHTTP(request, resp, body, nil, outputExtractorResults)
		result.GotResults = true
	}

	return nil
}

// Close closes the http executer for a template.
func (e *HTTPExecuter) Close() {
	e.outputMutex.Lock()
	defer e.outputMutex.Unlock()
	e.writer.Flush()
}

// makeHTTPClient creates a http client
func makeHTTPClient(proxyURL *url.URL, options *HTTPOptions) *retryablehttp.Client {
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = options.Retries
	followRedirects := options.BulkHttpRequest.Redirects
	maxRedirects := options.BulkHttpRequest.MaxRedirects

	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
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
		if err == nil {
			transport.Dial = dialer.Dial
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
			if len(requests) > 10 {
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

func (e *HTTPExecuter) setCustomHeaders(r *requests.HttpRequest) {
	for _, customHeader := range e.customHeaders {
		// This should be pre-computed somewhere and done only once
		tokens := strings.Split(customHeader, ":")
		// if it's an invalid header skip it
		if len(tokens) < 2 {
			continue
		}

		headerName, headerValue := tokens[0], strings.Join(tokens[1:], "")
		headerName = strings.TrimSpace(headerName)
		headerValue = strings.TrimSpace(headerValue)
		r.Request.Header[headerName] = []string{headerValue}
	}
}

type Result struct {
	Meta        map[string]interface{}
	Matches     map[string]interface{}
	Extractions map[string]interface{}
	GotResults  bool
	Error       error
	Done        bool
}
