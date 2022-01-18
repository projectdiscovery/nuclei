package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/race"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
)

// generatedRequest is a single generated request wrapped for a template request
type generatedRequest struct {
	original        *Request
	rawRequest      *raw.Request
	meta            map[string]interface{}
	pipelinedClient *rawhttp.PipelineClient
	request         *retryablehttp.Request
	dynamicValues   map[string]interface{}
	interactshURLs  []string
}

func (g *generatedRequest) URL() string {
	if g.request != nil {
		return g.request.URL.String()
	}
	if g.rawRequest != nil {
		return g.rawRequest.FullURL
	}
	return ""
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(baseURL, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	if r.request.SelfContained {
		return r.makeSelfContainedRequest(data, payloads, dynamicValues)
	}
	ctx := context.Background()

	if r.options.Interactsh != nil {

		data, r.interactshURLs = r.options.Interactsh.ReplaceMarkers(data, []string{})
		for payloadName, payloadValue := range payloads {
			payloads[payloadName], r.interactshURLs = r.options.Interactsh.ReplaceMarkers(types.ToString(payloadValue), r.interactshURLs)
		}
	} else {
		for payloadName, payloadValue := range payloads {
			payloads[payloadName] = types.ToString(payloadValue)
		}
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	data, parsed = baseURLWithTemplatePrefs(data, parsed)

	isRawRequest := len(r.request.Raw) > 0

	// If the request is not a raw request, and the URL input path is suffixed with
	// a trailing slash, and our Input URL is also suffixed with a trailing slash,
	// mark trailingSlash bool as true which will be later used during variable generation
	// to generate correct path removed slash which would otherwise generate // invalid sequence.
	// TODO: Figure out a cleaner way to do this sanitization.
	trailingSlash := false
	if !isRawRequest && strings.HasSuffix(parsed.Path, "/") && strings.Contains(data, "{{BaseURL}}/") {
		trailingSlash = true
	}

	values := generators.MergeMaps(
		generators.MergeMaps(dynamicValues, generateVariables(parsed, trailingSlash)),
		generators.BuildPayloadFromOptions(r.request.options.Options),
	)

	// If data contains \n it's a raw request, process it like raw. Else
	// continue with the template based request flow.
	if isRawRequest {
		return r.makeHTTPRequestFromRaw(ctx, parsed.String(), data, values, payloads)
	}
	return r.makeHTTPRequestFromModel(ctx, data, values, payloads)
}

func (r *requestGenerator) makeSelfContainedRequest(data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	ctx := context.Background()

	isRawRequest := r.request.isRaw()

	// If the request is a raw request, get the URL from the request
	// header and use it to make the request.
	if isRawRequest {
		// Get the hostname from the URL section to build the request.
		reader := bufio.NewReader(strings.NewReader(data))
		s, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("could not read request: %w", err)
		}

		parts := strings.Split(s, " ")
		if len(parts) < 3 {
			return nil, fmt.Errorf("malformed request supplied")
		}

		payloads = generators.MergeMaps(
			payloads,
			generators.BuildPayloadFromOptions(r.request.options.Options),
		)

		// in case cases (eg requests signing, some variables uses default values if missing)
		if defaultList := GetVariablesDefault(r.request.Signature.Value); defaultList != nil {
			payloads = generators.MergeMaps(defaultList, payloads)
		}

		parts[1] = replacer.Replace(parts[1], payloads)
		if len(dynamicValues) > 0 {
			parts[1] = replacer.Replace(parts[1], dynamicValues)
		}

		// the url might contain placeholders with ignore list
		if ignoreList := GetVariablesNamesSkipList(r.request.Signature.Value); ignoreList != nil {
			if err := expressions.ContainsVariablesWithIgnoreList(ignoreList, parts[1]); err != nil {
				return nil, err
			}
		} else { // the url might contain placeholders
			if err := expressions.ContainsUnresolvedVariables(parts[1]); err != nil {
				return nil, err
			}
		}

		parsed, err := url.Parse(parts[1])
		if err != nil {
			return nil, fmt.Errorf("could not parse request URL: %w", err)
		}
		values := generators.MergeMaps(
			generators.MergeMaps(dynamicValues, generateVariables(parsed, false)),
			payloads,
		)

		return r.makeHTTPRequestFromRaw(ctx, parsed.String(), data, values, payloads)
	}
	values := generators.MergeMaps(
		dynamicValues,
		generators.BuildPayloadFromOptions(r.request.options.Options),
	)
	return r.makeHTTPRequestFromModel(ctx, data, values, payloads)
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
func (r *requestGenerator) makeHTTPRequestFromModel(ctx context.Context, data string, values, generatorValues map[string]interface{}) (*generatedRequest, error) {
	if r.options.Interactsh != nil {
		data, r.interactshURLs = r.options.Interactsh.ReplaceMarkers(data, r.interactshURLs)
	}

	// Combine the template payloads along with base
	// request values.
	finalValues := generators.MergeMaps(generatorValues, values)

	// Evaluate the expressions for the request if any.
	var err error
	data, err = expressions.Evaluate(data, finalValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not evaluate helper expressions")
	}

	method, err := expressions.Evaluate(r.request.Method.String(), finalValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not evaluate helper expressions")
	}

	// Build a request on the specified URL
	req, err := http.NewRequestWithContext(ctx, method, data, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, finalValues)
	if err != nil {
		return nil, err
	}
	return &generatedRequest{request: request, meta: generatorValues, original: r.request, dynamicValues: finalValues, interactshURLs: r.interactshURLs}, nil
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *requestGenerator) makeHTTPRequestFromRaw(ctx context.Context, baseURL, data string, values, payloads map[string]interface{}) (*generatedRequest, error) {
	if r.options.Interactsh != nil {
		data, r.interactshURLs = r.options.Interactsh.ReplaceMarkers(data, r.interactshURLs)
	}
	return r.handleRawWithPayloads(ctx, data, baseURL, values, payloads)
}

// handleRawWithPayloads handles raw requests along with payloads
func (r *requestGenerator) handleRawWithPayloads(ctx context.Context, rawRequest, baseURL string, values, generatorValues map[string]interface{}) (*generatedRequest, error) {
	// Combine the template payloads along with base
	// request values.
	finalValues := generators.MergeMaps(generatorValues, values)

	// Evaluate the expressions for raw request if any.
	var err error
	rawRequest, err = expressions.Evaluate(rawRequest, finalValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not evaluate helper expressions")
	}
	rawRequestData, err := raw.Parse(rawRequest, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		if len(r.options.Options.CustomHeaders) > 0 {
			_ = rawRequestData.TryFillCustomHeaders(r.options.Options.CustomHeaders)
		}
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
		if key == "" {
			continue
		}
		req.Header[key] = []string{value}
		if key == "Host" {
			req.Host = value
		}
	}
	request, err := r.fillRequest(req, finalValues)
	if err != nil {
		return nil, err
	}

	return &generatedRequest{request: request, meta: generatorValues, original: r.request, dynamicValues: finalValues, interactshURLs: r.interactshURLs}, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	// Set the header values requested
	for header, value := range r.request.Headers {
		if r.options.Interactsh != nil {
			value, r.interactshURLs = r.options.Interactsh.ReplaceMarkers(value, r.interactshURLs)
		}
		value, err := expressions.Evaluate(value, values)
		if err != nil {
			return nil, errors.Wrap(err, "could not evaluate helper expressions")
		}
		req.Header[header] = []string{value}
		if header == "Host" {
			req.Host = value
		}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	if r.request.Threads <= 0 && req.Header.Get("Connection") == "" {
		req.Close = true
	}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body := r.request.Body
		if r.options.Interactsh != nil {
			body, r.interactshURLs = r.options.Interactsh.ReplaceMarkers(r.request.Body, r.interactshURLs)
		}
		body, err := expressions.Evaluate(body, values)
		if err != nil {
			return nil, errors.Wrap(err, "could not evaluate helper expressions")
		}
		req.Body = ioutil.NopCloser(strings.NewReader(body))
	}
	if !r.request.Unsafe {
		setHeader(req, "User-Agent", uarand.GetRandom())
	}

	// Only set these headers on non-raw requests
	if len(r.request.Raw) == 0 && !r.request.Unsafe {
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
	if name == "Host" {
		req.Host = value
	}
}

// generateVariables will create default variables after parsing a url
func generateVariables(parsed *url.URL, trailingSlash bool) map[string]interface{} {
	domain := parsed.Host
	if strings.Contains(parsed.Host, ":") {
		domain = strings.Split(parsed.Host, ":")[0]
	}

	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else if parsed.Scheme == "http" {
			port = "80"
		}
	}

	if trailingSlash {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}

	escapedPath := parsed.EscapedPath()
	directory := path.Dir(escapedPath)
	if directory == "." {
		directory = ""
	}
	base := path.Base(escapedPath)
	if base == "." {
		base = ""
	}
	httpVariables := map[string]interface{}{
		"BaseURL":  parsed.String(),
		"RootURL":  fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host),
		"Hostname": parsed.Host,
		"Host":     domain,
		"Port":     port,
		"Path":     directory,
		"File":     base,
		"Scheme":   parsed.Scheme,
	}
	return generators.MergeMaps(httpVariables, dns.GenerateDNSVariables(domain))
}
