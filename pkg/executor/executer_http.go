package executor

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/projectdiscovery/gologger"
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
}

// NewHTTPExecutor creates a new HTTP executor from a template
// and a HTTP request query.
func NewHTTPExecutor(template *templates.Template, httpRequest *requests.HTTPRequest) *HTTPExecutor {
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = r.options.Retries

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
		Timeout: time.Duration(r.options.Timeout) * time.Second,
		CheckRedirect: func(_ *http.Request, requests []*http.Request) error {
			if !httpRequest.Redirects {
				return http.ErrUseLastResponse
			}
			if httpRequest.MaxRedirects == 0 {
				if len(requests) > 10 {
					return http.ErrUseLastResponse
				}
				return nil
			}
			if len(requests) > httpRequest.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, retryablehttpOptions)
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	executer := &HTTPExecutor{
		httpClient:  client,
		template:    template,
		httpRequest: httpRequest,
	}
	return executer
}

// ExecuteHTTP executes the HTTP request on a URL
func (e *HTTPExecutor) ExecuteHTTP(URL string) {
	if !isURL(URL) {
		return
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := e.httpRequest.MakeHTTPRequest(URL)
	if err != nil {
		gologger.Warningf("[%s] Could not make request %s: %s\n", e.template.ID, URL, err)
		return
	}

	// Send the request to the target servers
	for _, req := range compiledRequest {
		resp, err := e.httpClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			gologger.Warningf("[%s] Could not send request %s: %s\n", e.template.ID, URL, err)
			return
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			gologger.Warningf("[%s] Could not read body %s: %s\n", e.template.ID, URL, err)
			continue
		}
		resp.Body.Close()

		body := unsafeToString(data)

		var headers string
		for _, matcher := range e.httpRequest.Matchers {
			// Only build the headers string if the matcher asks for it
			part := matcher.GetPart()
			if part == matchers.AllPart || part == matchers.HeaderPart && headers == "" {
				headers = headersToString(resp.Header)
			}

			// Check if the matcher matched
			if matcher.Match(resp, body, headers) {
				// If there is an extractor, run it.
				var extractorResults []string
				for _, extractor := range e.httpRequest.Extractors {
					part := extractor.GetPart()
					if part == extractors.AllPart || part == extractors.HeaderPart && headers == "" {
						headers = headersToString(resp.Header)
					}
					extractorResults = append(extractorResults, extractor.Extract(body, headers)...)
				}
			}
		}
	}
}
