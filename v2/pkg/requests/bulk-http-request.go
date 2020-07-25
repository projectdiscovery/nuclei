package requests

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// BulkHTTPRequest contains a request to be made from a template
type BulkHTTPRequest struct {
	Name string `yaml:"Name,omitempty"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `yaml:"attack,omitempty"`
	// attackType is internal attack type
	attackType generators.Type
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `yaml:"method"`
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `yaml:"body,omitempty"`
	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `yaml:"cookie-reuse,omitempty"`
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `yaml:"max-redirects,omitempty"`
	// Raw contains raw requests
	Raw  []string `yaml:"raw,omitempty"`
	gsfm *GeneratorFSM
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

func (r *BulkHTTPRequest) MakeHTTPRequest(baseURL string, dynamicValues map[string]interface{}, data string) (*HttpRequest, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	hostname := parsed.Host

	values := generators.MergeMaps(dynamicValues, map[string]interface{}{
		"BaseURL":  baseURL,
		"Hostname": hostname,
	})

	// if data contains \n it's a raw request
	if strings.Contains(data, "\n") {
		return r.makeHTTPRequestFromRaw(baseURL, data, values)
	}

	return r.makeHTTPRequestFromModel(baseURL, data, values)
}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *BulkHTTPRequest) makeHTTPRequestFromModel(baseURL string, data string, values map[string]interface{}) (*HttpRequest, error) {
	replacer := newReplacer(values)
	URL := replacer.Replace(data)

	// Build a request on the specified URL
	req, err := http.NewRequest(r.Method, URL, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}

	return &HttpRequest{Request: request}, nil
}

func (r *BulkHTTPRequest) InitGenerator() {
	r.gsfm = NewGeneratorFSM(r.attackType, r.Payloads, r.Path, r.Raw)
}

func (r *BulkHTTPRequest) CreateGenerator(URL string) {
	r.gsfm.Add(URL)
}

func (r *BulkHTTPRequest) HasGenerator(URL string) bool {
	return r.gsfm.Has(URL)
}

func (r *BulkHTTPRequest) ReadOne(URL string) {
	r.gsfm.ReadOne(URL)
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *BulkHTTPRequest) makeHTTPRequestFromRaw(baseURL string, data string, values map[string]interface{}) (*HttpRequest, error) {
	// Add trailing line
	data += "\n"
	if len(r.Payloads) > 0 {
		r.gsfm.InitOrSkip(baseURL)
		r.ReadOne(baseURL)
		return r.handleRawWithPaylods(data, baseURL, values, r.gsfm.Value(baseURL))
	}

	// otherwise continue with normal flow
	return r.handleRawWithPaylods(data, baseURL, values, nil)
}

func (r *BulkHTTPRequest) handleRawWithPaylods(raw string, baseURL string, values, genValues map[string]interface{}) (*HttpRequest, error) {
	baseValues := generators.CopyMap(values)
	finValues := generators.MergeMaps(baseValues, genValues)

	replacer := newReplacer(finValues)

	// Replace the dynamic variables in the URL if any
	raw = replacer.Replace(raw)

	dynamicValues := make(map[string]interface{})
	// find all potentials tokens between {{}}
	var re = regexp.MustCompile(`(?m)\{\{.+}}`)
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

	compiledRequest, err := r.parseRawRequest(raw, baseURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(compiledRequest.Method, compiledRequest.FullURL, strings.NewReader(compiledRequest.Data))
	if err != nil {
		return nil, err
	}

	// copy headers
	for key, value := range compiledRequest.Headers {
		req.Header[key] = []string{value}
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}

	return &HttpRequest{Request: request, Meta: genValues}, nil
}

func (r *BulkHTTPRequest) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	req.Header.Set("Connection", "close")
	req.Close = true
	replacer := newReplacer(values)

	// Check if the user requested a request body
	if r.Body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(r.Body))
	}

	// Set the header values requested
	for header, value := range r.Headers {
		req.Header[header] = []string{replacer.Replace(value)}
	}

	// Set some headers only if the header wasn't supplied by the user
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")
	}

	// raw requests are left untouched
	if len(r.Raw) > 0 {
		return retryablehttp.FromRequest(req)
	}

	if _, ok := req.Header["Accept"]; !ok {
		req.Header.Set("Accept", "*/*")
	}
	if _, ok := req.Header["Accept-Language"]; !ok {
		req.Header.Set("Accept-Language", "en")
	}

	return retryablehttp.FromRequest(req)
}

type HttpRequest struct {
	Request *retryablehttp.Request
	Meta    map[string]interface{}
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

type RawRequest struct {
	FullURL string
	Method  string
	Path    string
	Data    string
	Headers map[string]string
}

// parseRawRequest parses the raw request as supplied by the user
func (r *BulkHTTPRequest) parseRawRequest(request string, baseURL string) (*RawRequest, error) {
	reader := bufio.NewReader(strings.NewReader(request))

	rawRequest := RawRequest{
		Headers: make(map[string]string),
	}

	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %s", err)
	}
	parts := strings.Split(s, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if err != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}

		if strings.EqualFold(p[0], "content-length") {
			continue
		}

		rawRequest.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if strings.HasPrefix(parts[1], "http") {
		parsed, err := url.Parse(parts[1])
		if err != nil {
			return nil, fmt.Errorf("could not parse request URL: %s", err)
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
	if len(rawRequest.Headers["Host"]) == 0 {
		hostURL = parsedURL.Host
	} else {
		hostURL = rawRequest.Headers["Host"]
	}

	if len(rawRequest.Path) == 0 {
		rawRequest.Path = parsedURL.Path
	} else {
		// requests generated from http.ReadRequest have incorrect RequestURI, so they
		// cannot be used to perform another request directly, we need to generate a new one
		// with the new target url
		if strings.HasPrefix(rawRequest.Path, "?") {
			rawRequest.Path = fmt.Sprintf("%s%s", parsedURL.Path, rawRequest.Path)
		}
	}

	rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, hostURL, rawRequest.Path)

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}
	rawRequest.Data = string(b)
	return &rawRequest, nil
}

func (r *BulkHTTPRequest) Next(URL string) bool {
	return r.gsfm.Next(URL)
}
func (r *BulkHTTPRequest) Position(URL string) int {
	return r.gsfm.Position(URL)
}

func (r *BulkHTTPRequest) Reset(URL string) {
	r.gsfm.Reset(URL)
}

func (r *BulkHTTPRequest) Current(URL string) string {
	return r.gsfm.Current(URL)
}

func (r *BulkHTTPRequest) Total() int {
	return len(r.Path) + len(r.Raw)
}

func (r *BulkHTTPRequest) Increment(URL string) {
	r.gsfm.Increment(URL)
}
