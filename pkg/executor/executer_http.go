package executor

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/proxy"
)

// HTTPExecutor is client for performing HTTP requests
// for a template.
type HTTPExecutor struct {
	debug         bool
	results       uint32
	httpClient    *retryablehttp.Client
	template      *templates.Template
	httpRequest   *requests.HTTPRequest
	writer        *bufio.Writer
	outputMutex   *sync.Mutex
	customHeaders requests.CustomHeaders
}

// HTTPOptions contains configuration options for the HTTP executor.
type HTTPOptions struct {
	Template      *templates.Template
	HTTPRequest   *requests.HTTPRequest
	Writer        *bufio.Writer
	Timeout       int
	Retries       int
	ProxyURL      string
	ProxySocksURL string
	Debug         bool
	CustomHeaders requests.CustomHeaders
}

// NewHTTPExecutor creates a new HTTP executor from a template
// and a HTTP request query.
func NewHTTPExecutor(options *HTTPOptions) (*HTTPExecutor, error) {
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

	executer := &HTTPExecutor{
		debug:         options.Debug,
		results:       0,
		httpClient:    client,
		template:      options.Template,
		httpRequest:   options.HTTPRequest,
		outputMutex:   &sync.Mutex{},
		writer:        options.Writer,
		customHeaders: options.CustomHeaders,
	}
	return executer, nil
}

// GotResults returns true if there were any results for the executor
func (e *HTTPExecutor) GotResults() bool {
	if atomic.LoadUint32(&e.results) == 0 {
		return false
	}
	return true
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
	for compiledRequest := range compiledRequest {
		if compiledRequest.Error != nil {
			return errors.Wrap(err, "could not make http request")
		}
		e.setCustomHeaders(compiledRequest)
		req := compiledRequest.Request

		if e.debug {
			gologger.Infof("Dumped HTTP request for %s (%s)\n\n", URL, e.template.ID)
			dumpedRequest, err := httputil.DumpRequest(req.Request, true)
			if err != nil {
				return errors.Wrap(err, "could not dump http request")
			}
			fmt.Fprintf(os.Stderr, "%s", string(dumpedRequest))
		}

		resp, err := e.httpClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return errors.Wrap(err, "could not make http request")
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
		data, err = requests.HandleDecompression(compiledRequest.Request, data)
		if err != nil {
			return errors.Wrap(err, "could not decompress http body")
		}

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
					e.writeOutputHTTP(compiledRequest, matcher, nil)
					atomic.CompareAndSwapUint32(&e.results, 0, 1)
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
			e.writeOutputHTTP(compiledRequest, nil, extractorResults)
			atomic.CompareAndSwapUint32(&e.results, 0, 1)
		}
	}

	gologger.Verbosef("Sent HTTP request to %s\n", "http-request", URL)

	return nil
}

// Close closes the http executor for a template.
func (e *HTTPExecutor) Close() {
	e.outputMutex.Lock()
	e.writer.Flush()
	e.outputMutex.Unlock()
}

// makeHTTPClient creates a http client
func makeHTTPClient(proxyURL *url.URL, options *HTTPOptions) *retryablehttp.Client {
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = options.Retries
	followRedirects := options.HTTPRequest.Redirects
	maxRedirects := options.HTTPRequest.MaxRedirects

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

func (e *HTTPExecutor) setCustomHeaders(r *requests.CompiledHTTP) {
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
		r.Request.Header.Set(headerName, headerValue)
	}
}
