package executor

import (
	"bufio"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	"github.com/projectdiscovery/retryablehttp-go"
)

// HTTPExecutor is client for performing HTTP requests
// for a template.
type HTTPExecutor struct {
	httpClient  *retryablehttp.Client
	template    *templates.Template
	httpRequest *requests.HTTPRequest
	writer      *bufio.Writer
	outputMutex *sync.Mutex
}

// HTTPOptions contains configuration options for the HTTP executor.
type HTTPOptions struct {
	Template    *templates.Template
	HTTPRequest *requests.HTTPRequest
	Writer      *bufio.Writer
	Timeout     int
	Retries     int
}

// NewHTTPExecutor creates a new HTTP executor from a template
// and a HTTP request query.
func NewHTTPExecutor(options *HTTPOptions) *HTTPExecutor {
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = options.Retries
	followRedirects := options.HTTPRequest.Redirects
	maxRedirects := options.HTTPRequest.MaxRedirects

	// Create the HTTP Client
	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		},
		Timeout: time.Duration(options.Timeout) * time.Second,
		CheckRedirect: func(_ *http.Request, requests []*http.Request) error {
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
		},
	}, retryablehttpOptions)
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	executer := &HTTPExecutor{
		httpClient:  client,
		template:    options.Template,
		httpRequest: options.HTTPRequest,
		outputMutex: &sync.Mutex{},
		writer:      options.Writer,
	}
	return executer
}

// ExecuteHTTP executes the HTTP request on a URL
func (e *HTTPExecutor) ExecuteHTTP(URL string) error {
	// Compile each request for the template based on the URL
	compiledRequest, err := e.httpRequest.MakeHTTPRequest(URL)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}

	// Send the request to the target servers
mainLoop:
	for _, req := range compiledRequest {
		resp, err := e.httpClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return errors.Wrap(err, "could not make http request")
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			return errors.Wrap(err, "could not read http body")
		}
		resp.Body.Close()

		// Convert response body from []byte to string with zero copy
		body := unsafeToString(data)

		var headers string
		matcherCondition := e.httpRequest.GetMatchersCondition()
		for _, matcher := range e.httpRequest.Matchers {
			// Only build the headers string if the matcher asks for it
			part := matcher.GetPart()
			if part == matchers.AllPart || part == matchers.HeaderPart && headers == "" {
				headers = headersToString(resp.Header)
			}

			// Check if the matcher matched
			if !matcher.Match(resp, body, headers) {
				// If the condition is AND we haven't matched, try next request.
				if matcherCondition == matchers.ANDCondition {
					continue mainLoop
				}
			} else {
				// If the matcher has matched, and its an OR
				// write the first output then move to next matcher.
				if matcherCondition == matchers.ORCondition && len(e.httpRequest.Extractors) == 0 {
					e.writeOutputHTTP(req, matcher, nil)
				}
			}
		}

		// All matchers have successfully completed so now start with the
		// next task which is extraction of input from matchers.
		var extractorResults []string
		for _, extractor := range e.httpRequest.Extractors {
			part := extractor.GetPart()
			if part == extractors.AllPart || part == extractors.HeaderPart && headers == "" {
				headers = headersToString(resp.Header)
			}
			for match := range extractor.Extract(body, headers) {
				extractorResults = append(extractorResults, match)
			}
		}

		// Write a final string of output if matcher type is
		// AND or if we have extractors for the mechanism too.
		if len(e.httpRequest.Extractors) > 0 || matcherCondition == matchers.ANDCondition {
			e.writeOutputHTTP(req, nil, extractorResults)
		}
	}
	return nil
}

// Close closes the http executor for a template.
func (e *HTTPExecutor) Close() {
	e.outputMutex.Lock()
	e.writer.Flush()
	e.outputMutex.Unlock()
}
