package http

import (
	"context"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/race"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	urlWithPortRegex        = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
	templateExpressionRegex = regexp.MustCompile(`(?m)\{\{[^}]+\}\}`)
)

// generatedRequest is a single wrapped generated request for a template request
type generatedRequest struct {
	original        *Request
	rawRequest      *raw.Request
	meta            map[string]interface{}
	pipelinedClient *rawhttp.PipelineClient
	request         *retryablehttp.Request
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(baseURL string, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// We get the next payload for the request.
	data, payloads, ok := r.nextValue()
	if !ok {
		return nil, io.EOF
	}
	ctx := context.Background()

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	data, parsed = baseURLWithTemplatePrefs(data, parsed)
	values := generators.MergeMaps(dynamicValues, map[string]interface{}{
		"Hostname": parsed.Hostname(),
	})

	isRawRequest := strings.Contains(data, "\n")
	if !isRawRequest && strings.HasSuffix(parsed.Path, "/") && strings.Contains(data, "{{BaseURL}}/") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}
	parsedString := parsed.String()
	values["BaseURL"] = parsedString

	// If data contains \n it's a raw request, process it like raw. Else
	// continue with the template based request flow.
	if isRawRequest {
		return r.makeHTTPRequestFromRaw(ctx, parsedString, data, values, payloads)
	}
	return r.makeHTTPRequestFromModel(ctx, data, values)
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	if r.payloadIterator != nil {
		return len(r.request.Raw) * r.payloadIterator.Remaining()
	}
	return len(r.request.Path)
}

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference over the user provided one.
func baseURLWithTemplatePrefs(data string, parsed *url.URL) (string, *url.URL) {
	// template port preference over input URL port if template has a port
	matches := urlWithPortRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return data, parsed
	}
	port := matches[0][1]
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	data = strings.ReplaceAll(data, ":"+port, "")
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return data, parsed
}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *requestGenerator) makeHTTPRequestFromModel(ctx context.Context, data string, values map[string]interface{}) (*generatedRequest, error) {
	final := replacer.Replace(data, values)

	// Build a request on the specified URL
	req, err := http.NewRequestWithContext(ctx, r.request.Method, final, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}
	return &generatedRequest{request: request, original: r.request}, nil
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *requestGenerator) makeHTTPRequestFromRaw(ctx context.Context, baseURL, data string, values, payloads map[string]interface{}) (*generatedRequest, error) {
	data += "\r\n"
	return r.handleRawWithPaylods(ctx, data, baseURL, values, payloads)
}

// handleRawWithPaylods handles raw requests along with paylaods
func (r *requestGenerator) handleRawWithPaylods(ctx context.Context, rawRequest, baseURL string, values, generatorValues map[string]interface{}) (*generatedRequest, error) {
	// Combine the template payloads along with base
	// request values.
	finalValues := generators.MergeMaps(generatorValues, values)
	rawRequest = replacer.Replace(rawRequest, finalValues)

	// Check if the match contains a dynamic variable, for each
	// found one we will check if it's an expression and can
	// be compiled, it will be evaluated and the results will be returned.
	//
	// The provided keys from finalValues will be used as variable names
	// for substitution inside the expression.
	dynamicValues := make(map[string]interface{})
	for _, match := range templateExpressionRegex.FindAllString(rawRequest, -1) {
		expr := generators.TrimDelimiters(match)

		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, dsl.HelperFunctions())
		if err != nil {
			return nil, err
		}
		result, err := compiled.Evaluate(finalValues)
		if err != nil {
			return nil, err
		}
		dynamicValues[expr] = result // convert base64(<payload_name>) => <base64-representation>
	}

	// Replacer dynamic values if any in raw request and parse it
	rawRequest = replacer.Replace(rawRequest, dynamicValues)
	rawRequestData, err := raw.Parse(rawRequest, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		unsafeReq := &generatedRequest{rawRequest: rawRequestData, meta: generatorValues, original: r.request}
		return unsafeReq, nil
	}

	// retryablehttp
	var body io.ReadCloser
	body = ioutil.NopCloser(strings.NewReader(rawRequestData.Data))
	if r.request.Race {
		// More or less this ensures that all requests hit the endpoint at the same approximated time
		// Todo: sync internally upon writing latest request byte
		body = race.NewOpenGateWithTimeout(body, time.Duration(2)*time.Second)
	}

	req, err := http.NewRequestWithContext(ctx, rawRequestData.Method, rawRequestData.FullURL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range rawRequestData.Headers {
		req.Header[key] = []string{value}
	}
	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}
	return &generatedRequest{request: request, meta: generatorValues, original: r.request}, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	// Set the header values requested
	for header, value := range r.request.Headers {
		req.Header[header] = []string{replacer.Replace(value, values)}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	if r.request.Threads <= 0 && req.Header.Get("Connection") == "" {
		req.Close = true
	}

	// Check if the user requested a request body
	if r.request.Body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(r.request.Body))
	}
	setHeader(req, "User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")

	// Only set these headers on non raw requests
	if len(r.request.Raw) == 0 {
		setHeader(req, "Accept", "*/*")
		setHeader(req, "Accept-Language", "en")
	}
	return retryablehttp.FromRequest(req)
}

// setHeader sets some headers only if the header wasn't supplied by the user
func setHeader(req *http.Request, name, value string) {
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
}
