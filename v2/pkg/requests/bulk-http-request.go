package requests

import (
	"bufio"
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
	"github.com/projectdiscovery/nuclei/v2/pkg/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/syncedreadcloser"
	"github.com/projectdiscovery/rawhttp"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

const (
	two   = 2
	three = 3
)

var urlWithPortRgx = regexp.MustCompile(`{{BaseURL}}:(\d+)`)

// BulkHTTPRequest contains a request to be made from a template
type BulkHTTPRequest struct {
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// Raw contains raw requests
	Raw  []string `yaml:"raw,omitempty"`
	Name string   `yaml:"Name,omitempty"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `yaml:"attack,omitempty"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `yaml:"method"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `yaml:"body,omitempty"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
	// attackType is internal attack type
	attackType generators.Type
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty"`
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects                  int `yaml:"max-redirects,omitempty"`
	PipelineConcurrentConnections int `yaml:"pipeline-concurrent-connections,omitempty"`
	PipelineRequestsPerConnection int `yaml:"pipeline-requests-per-connection,omitempty"`
	Threads                       int `yaml:"threads,omitempty"`
	// Internal Finite State Machine keeping track of scan process
	gsfm *GeneratorFSM
	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `yaml:"cookie-reuse,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects,omitempty"`
	// Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining (race conditions/billions requests)
	// All requests must be indempotent (GET/POST)
	Pipeline bool `yaml:"pipeline,omitempty"`
	// Specify in order to skip request RFC normalization
	Unsafe bool `yaml:"unsafe,omitempty"`
	// DisableAutoHostname Enable/Disable Host header for unsafe raw requests
	DisableAutoHostname bool `yaml:"disable-automatic-host-header,omitempty"`
	// DisableAutoContentLength Enable/Disable Content-Length header for unsafe raw requests
	DisableAutoContentLength bool `yaml:"disable-automatic-content-length-header,omitempty"`
	// Race determines if all the request have to be attempted at the same time
	// The minimum number fof requests is determined by threads
	Race bool `yaml:"race,omitempty"`
	// Number of same request to send in race condition attack
	RaceNumberRequests int `yaml:"race_count,omitempty"`
}

// GetMatchersCondition returns the condition for the matcher
func (r *BulkHTTPRequest) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// SetMatchersCondition sets the condition for the matcher
func (r *BulkHTTPRequest) SetMatchersCondition(condition matchers.ConditionType) {
	r.matchersCondition = condition
}

// GetAttackType returns the attack
func (r *BulkHTTPRequest) GetAttackType() generators.Type {
	return r.attackType
}

// SetAttackType sets the attack
func (r *BulkHTTPRequest) SetAttackType(attack generators.Type) {
	r.attackType = attack
}

// GetRequestCount returns the total number of requests the YAML rule will perform
func (r *BulkHTTPRequest) GetRequestCount() int64 {
	return int64(r.gsfm.Total())
}

// MakeHTTPRequest makes the HTTP request
func (r *BulkHTTPRequest) MakeHTTPRequest(baseURL string, dynamicValues map[string]interface{}, data string) (*HTTPRequest, error) {
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
func (r *BulkHTTPRequest) makeHTTPRequestFromModel(ctx context.Context, data string, values map[string]interface{}) (*HTTPRequest, error) {
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
func (r *BulkHTTPRequest) InitGenerator() {
	r.gsfm = NewGeneratorFSM(r.attackType, r.Payloads, r.Path, r.Raw)
}

// CreateGenerator creates the generator
func (r *BulkHTTPRequest) CreateGenerator(reqURL string) {
	r.gsfm.Add(reqURL)
}

// HasGenerator check if an URL has a generator
func (r *BulkHTTPRequest) HasGenerator(reqURL string) bool {
	return r.gsfm.Has(reqURL)
}

// ReadOne reads and return a generator by URL
func (r *BulkHTTPRequest) ReadOne(reqURL string) {
	r.gsfm.ReadOne(reqURL)
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *BulkHTTPRequest) makeHTTPRequestFromRaw(ctx context.Context, baseURL, data string, values map[string]interface{}) (*HTTPRequest, error) {
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

func (r *BulkHTTPRequest) handleRawWithPaylods(ctx context.Context, raw, baseURL string, values, genValues map[string]interface{}) (*HTTPRequest, error) {
	baseValues := generators.CopyMap(values)
	finValues := generators.MergeMaps(baseValues, genValues)

	replacer := newReplacer(finValues)

	// Replace the dynamic variables in the URL if any
	raw = replacer.Replace(raw)

	dynamicValues := make(map[string]interface{})
	// find all potentials tokens between {{}}
	var re = regexp.MustCompile(`(?m)\{\{[^}]+\}\}`)
	for _, match := range re.FindAllString(raw, -1) {
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

	// replace dynamic values
	dynamicReplacer := newReplacer(dynamicValues)
	raw = dynamicReplacer.Replace(raw)

	rawRequest, err := r.parseRawRequest(raw, baseURL)
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
		body = syncedreadcloser.NewOpenGateWithTimeout(body, time.Duration(two)*time.Second)
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

func (r *BulkHTTPRequest) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	replacer := newReplacer(values)
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

// HTTPRequest is the basic HTTP request
type HTTPRequest struct {
	Request    *retryablehttp.Request
	RawRequest *RawRequest
	Meta       map[string]interface{}

	// flags
	Unsafe                       bool
	Pipeline                     bool
	AutomaticHostHeader          bool
	AutomaticContentLengthHeader bool
	AutomaticConnectionHeader    bool
	FollowRedirects              bool
	Rawclient                    *rawhttp.Client
	Httpclient                   *retryablehttp.Client
	PipelineClient               *rawhttp.PipelineClient
}

func setHeader(req *http.Request, name, value string) {
	// Set some headers only if the header wasn't supplied by the user
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
}

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference
func baseURLWithTemplatePrefs(data string, parsedURL *url.URL) string {
	// template port preference over input URL port
	// template has port
	hasPort := len(urlWithPortRgx.FindStringSubmatch(data)) > 0
	if hasPort {
		// check if also the input contains port, in this case extracts the url
		if hostname, _, err := net.SplitHostPort(parsedURL.Host); err == nil {
			parsedURL.Host = hostname
		}
	}

	return parsedURL.String()
}

// CustomHeaders valid for all requests
type CustomHeaders []string

// String returns just a label
func (c *CustomHeaders) String() string {
	return "Custom Global Headers"
}

// Set a new global header
func (c *CustomHeaders) Set(value string) error {
	*c = append(*c, value)
	return nil
}

// RawRequest defines a basic HTTP raw request
type RawRequest struct {
	FullURL string
	Method  string
	Path    string
	Data    string
	Headers map[string]string
}

// parseRawRequest parses the raw request as supplied by the user
func (r *BulkHTTPRequest) parseRawRequest(request, baseURL string) (*RawRequest, error) {
	reader := bufio.NewReader(strings.NewReader(request))

	rawRequest := RawRequest{
		Headers: make(map[string]string),
	}

	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %s", err)
	}

	parts := strings.Split(s, " ")

	if len(parts) < three {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	// Accepts all malformed headers
	var key, value string
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", two)
		key = p[0]
		if len(p) > 1 {
			value = p[1]
		}

		// in case of unsafe requests multiple headers should be accepted
		// therefore use the full line as key
		_, found := rawRequest.Headers[key]
		if r.Unsafe && found {
			rawRequest.Headers[line] = ""
		} else {
			rawRequest.Headers[key] = value
		}
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if !r.Unsafe && strings.HasPrefix(parts[1], "http") {
		parsed, parseErr := url.Parse(parts[1])
		if parseErr != nil {
			return nil, fmt.Errorf("could not parse request URL: %s", parseErr)
		}

		rawRequest.Path = parts[1]
		rawRequest.Headers["Host"] = parsed.Host
	} else {
		rawRequest.Path = parts[1]
	}

	// If raw request doesn't have a Host header and/ path,
	// this will be generated from the parsed baseURL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %s", err)
	}

	var hostURL string
	if rawRequest.Headers["Host"] == "" {
		hostURL = parsedURL.Host
	} else {
		hostURL = rawRequest.Headers["Host"]
	}

	if rawRequest.Path == "" {
		rawRequest.Path = parsedURL.Path
	} else if strings.HasPrefix(rawRequest.Path, "?") {
		// requests generated from http.ReadRequest have incorrect RequestURI, so they
		// cannot be used to perform another request directly, we need to generate a new one
		// with the new target url
		rawRequest.Path = fmt.Sprintf("%s%s", parsedURL.Path, rawRequest.Path)
	}

	rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, strings.TrimSpace(hostURL), rawRequest.Path)

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}

	rawRequest.Data = string(b)

	return &rawRequest, nil
}

// Next returns the next generator by URL
func (r *BulkHTTPRequest) Next(reqURL string) bool {
	return r.gsfm.Next(reqURL)
}

// Position returns the current generator's position by URL
func (r *BulkHTTPRequest) Position(reqURL string) int {
	return r.gsfm.Position(reqURL)
}

// Reset resets the generator by URL
func (r *BulkHTTPRequest) Reset(reqURL string) {
	r.gsfm.Reset(reqURL)
}

// Current returns the current generator by URL
func (r *BulkHTTPRequest) Current(reqURL string) string {
	return r.gsfm.Current(reqURL)
}

// Total is the total number of requests
func (r *BulkHTTPRequest) Total() int {
	return r.gsfm.Total()
}

// Increment increments the processed request
func (r *BulkHTTPRequest) Increment(reqURL string) {
	r.gsfm.Increment(reqURL)
}

// GetPayloadsValues for the specified URL
func (r *BulkHTTPRequest) GetPayloadsValues(reqURL string) (map[string]interface{}, error) {
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
