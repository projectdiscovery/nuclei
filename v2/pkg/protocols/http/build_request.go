package http

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/pkg/protcols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/race"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	"github.com/projectdiscovery/retryablehttp-go"
)

var urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)

// MakeHTTPRequest makes the HTTP request
func (r *Request) MakeHTTPRequest(baseURL string, dynamicValues map[string]interface{}, data string) (*HTTPRequest, error) {
	ctx := context.Background()

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	hostname := parsed.Host

	values := generators.MergeMaps(dynamicValues, map[string]interface{}{
		"BaseURL":  baseURLWithTemplatePrefs(data, parsed),
		"Hostname": hostname,
	})

	// if data contains \n it's a raw request
	if strings.Contains(data, "\n") {
		return r.makeHTTPRequestFromRaw(ctx, baseURL, data, values)
	}
	return r.makeHTTPRequestFromModel(ctx, data, values)
}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *Request) makeHTTPRequestFromModel(ctx context.Context, data string, values map[string]interface{}) (*HTTPRequest, error) {
	replacer := newReplacer(values)
	URL := replacer.Replace(data)

	// Build a request on the specified URL
	req, err := http.NewRequestWithContext(ctx, r.Method, URL, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}
	return &HTTPRequest{Request: request}, nil
}

// InitGenerator initializes the generator
func (r *Request) InitGenerator() {
	r.gsfm = NewGeneratorFSM(r.attackType, r.Payloads, r.Path, r.Raw)
}

// CreateGenerator creates the generator
func (r *Request) CreateGenerator(reqURL string) {
	r.gsfm.Add(reqURL)
}

// HasGenerator check if an URL has a generator
func (r *Request) HasGenerator(reqURL string) bool {
	return r.gsfm.Has(reqURL)
}

// ReadOne reads and return a generator by URL
func (r *Request) ReadOne(reqURL string) {
	r.gsfm.ReadOne(reqURL)
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *Request) makeHTTPRequestFromRaw(ctx context.Context, baseURL, data string, values map[string]interface{}) (*HTTPRequest, error) {
	// Add trailing line
	data += "\n"

	if len(r.Payloads) > 0 {
		r.gsfm.InitOrSkip(baseURL)
		r.ReadOne(baseURL)

		payloads, err := r.GetPayloadsValues(baseURL)
		if err != nil {
			return nil, err
		}

		return r.handleRawWithPaylods(ctx, data, baseURL, values, payloads)
	}

	// otherwise continue with normal flow
	return r.handleRawWithPaylods(ctx, data, baseURL, values, nil)
}

func (r *Request) handleRawWithPaylods(ctx context.Context, rawRequest, baseURL string, values, genValues map[string]interface{}) (*HTTPRequest, error) {
	baseValues := generators.CopyMap(values)
	finValues := generators.MergeMaps(baseValues, genValues)

	// Replace the dynamic variables in the URL if any
	rawRequest = replacer.New(finValues).Replace(rawRequest)

	dynamicValues := make(map[string]interface{})
	// find all potentials tokens between {{}}
	var re = regexp.MustCompile(`(?m)\{\{[^}]+\}\}`)
	for _, match := range re.FindAllString(rawRequest, -1) {
		// check if the match contains a dynamic variable
		expr := generators.TrimDelimiters(match)
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, generators.HelperFunctions())

		if err != nil {
			return nil, err
		}

		result, err := compiled.Evaluate(finValues)
		if err != nil {
			return nil, err
		}
		dynamicValues[expr] = result
	}

	// Replacer dynamic values if any in raw request and parse it
	rawRequest = replacer.New(dynamicValues).Replace(rawRequest)
	rawRequestData, err := raw.Parse(rawRequest, baseURL, r.Unsafe)
	if err != nil {
		return nil, err
	}

	// rawhttp
	if r.Unsafe {
		unsafeReq := &HTTPRequest{
			RawRequest:                   rawRequest,
			Meta:                         genValues,
			AutomaticHostHeader:          !r.DisableAutoHostname,
			AutomaticContentLengthHeader: !r.DisableAutoContentLength,
			Unsafe:                       true,
			FollowRedirects:              r.Redirects,
		}
		return unsafeReq, nil
	}

	// retryablehttp
	var body io.ReadCloser
	body = ioutil.NopCloser(strings.NewReader(rawRequest.Data))
	if r.Race {
		// More or less this ensures that all requests hit the endpoint at the same approximated time
		// Todo: sync internally upon writing latest request byte
		body = race.NewOpenGateWithTimeout(body, time.Duration(2)*time.Second)
	}

	req, err := http.NewRequestWithContext(ctx, rawRequest.Method, rawRequest.FullURL, body)
	if err != nil {
		return nil, err
	}

	// copy headers
	for key, value := range rawRequest.Headers {
		req.Header[key] = []string{value}
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}

	return &HTTPRequest{Request: request, Meta: genValues}, nil
}

func (r *Request) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	replacer := replacer.New(values)
	// Set the header values requested
	for header, value := range r.Headers {
		req.Header[header] = []string{replacer.Replace(value)}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	if r.Threads <= 0 && req.Header.Get("Connection") == "" {
		req.Close = true
	}

	// Check if the user requested a request body
	if r.Body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(r.Body))
	}
	setHeader(req, "User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")

	// raw requests are left untouched
	if len(r.Raw) > 0 {
		return retryablehttp.FromRequest(req)
	}
	setHeader(req, "Accept", "*/*")
	setHeader(req, "Accept-Language", "en")

	return retryablehttp.FromRequest(req)
}

// setHeader sets some headers only if the header wasn't supplied by the user
func setHeader(req *http.Request, name, value string) {
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
}

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference
func baseURLWithTemplatePrefs(data string, parsedURL *url.URL) string {
	// template port preference over input URL port
	// template has port
	hasPort := len(urlWithPortRegex.FindStringSubmatch(data)) > 0
	if hasPort {
		// check if also the input contains port, in this case extracts the url
		if hostname, _, err := net.SplitHostPort(parsedURL.Host); err == nil {
			parsedURL.Host = hostname
		}
	}
	return parsedURL.String()
}

// Next returns the next generator by URL
func (r *Request) Next(reqURL string) bool {
	return r.gsfm.Next(reqURL)
}

// Position returns the current generator's position by URL
func (r *Request) Position(reqURL string) int {
	return r.gsfm.Position(reqURL)
}

// Reset resets the generator by URL
func (r *Request) Reset(reqURL string) {
	r.gsfm.Reset(reqURL)
}

// Current returns the current generator by URL
func (r *Request) Current(reqURL string) string {
	return r.gsfm.Current(reqURL)
}

// Total is the total number of requests
func (r *Request) Total() int {
	return r.gsfm.Total()
}

// Increment increments the processed request
func (r *Request) Increment(reqURL string) {
	r.gsfm.Increment(reqURL)
}

// GetPayloadsValues for the specified URL
func (r *Request) GetPayloadsValues(reqURL string) (map[string]interface{}, error) {
	payloadProcessedValues := make(map[string]interface{})
	payloadsFromTemplate := r.gsfm.Value(reqURL)
	for k, v := range payloadsFromTemplate {
		kexp := v.(string)
		// if it doesn't containing markups, we just continue
		if !hasMarker(kexp) {
			payloadProcessedValues[k] = v
			continue
		}
		// attempts to expand expressions
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(kexp, generators.HelperFunctions())
		if err != nil {
			// it is a simple literal payload => proceed with literal value
			payloadProcessedValues[k] = v
			continue
		}
		// it is an expression - try to solve it
		expValue, err := compiled.Evaluate(payloadsFromTemplate)
		if err != nil {
			// an error occurred => proceed with literal value
			payloadProcessedValues[k] = v
			continue
		}
		payloadProcessedValues[k] = fmt.Sprint(expValue)
	}
	var err error
	if len(payloadProcessedValues) == 0 {
		err = ErrNoPayload
	}
	return payloadProcessedValues, err
}

// ErrNoPayload error to avoid the additional base null request
var ErrNoPayload = fmt.Errorf("no payload found")
