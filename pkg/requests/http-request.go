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
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/generators"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// HTTPRequest contains a request to be made from a template
type HTTPRequest struct {
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `yaml:"attack,omitempty"`
	// attackType is internal attack type
	attackType generators.Type
	// Path contains the path/s for the request variables
	Payloads map[string]string `yaml:"payloads,omitempty"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `yaml:"method"`
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `yaml:"body,omitempty"`
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
	Raw []string `yaml:"raw,omitempty"`
}

// GetMatchersCondition returns the condition for the matcher
func (r *HTTPRequest) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// SetMatchersCondition sets the condition for the matcher
func (r *HTTPRequest) SetMatchersCondition(condition matchers.ConditionType) {
	r.matchersCondition = condition
}

// GetAttackType returns the attack
func (r *HTTPRequest) GetAttackType() generators.Type {
	return r.attackType
}

// SetAttackType sets the attack
func (r *HTTPRequest) SetAttackType(attack generators.Type) {
	r.attackType = attack
}

// MakeHTTPRequest creates a *http.Request from a request configuration
func (r *HTTPRequest) MakeHTTPRequest(baseURL string) (chan *CompiledHTTP, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	hostname := parsed.Hostname()

	values := map[string]interface{}{
		"BaseURL":  baseURL,
		"Hostname": hostname,
	}

	if len(r.Raw) > 0 {
		return r.makeHTTPRequestFromRaw(baseURL, values)
	}

	return r.makeHTTPRequestFromModel(baseURL, values)
}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *HTTPRequest) makeHTTPRequestFromModel(baseURL string, values map[string]interface{}) (requests chan *CompiledHTTP, err error) {
	requests = make(chan *CompiledHTTP)

	// request generator
	go func() {
		defer close(requests)
		for _, path := range r.Path {
			// process base request
			replacer := newReplacer(values)

			// Replace the dynamic variables in the URL if any
			URL := replacer.Replace(path)

			// Build a request on the specified URL
			req, err := http.NewRequest(r.Method, URL, nil)
			if err != nil {
				requests <- &CompiledHTTP{Request: nil, Error: err, Meta: nil}
				return
			}

			request, err := r.fillRequest(req, values)
			if err != nil {
				requests <- &CompiledHTTP{Request: nil, Error: err, Meta: nil}
				return
			}

			requests <- &CompiledHTTP{Request: request, Error: nil, Meta: nil}
		}
	}()

	return
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *HTTPRequest) makeHTTPRequestFromRaw(baseURL string, values map[string]interface{}) (requests chan *CompiledHTTP, err error) {
	requests = make(chan *CompiledHTTP)
	// request generator
	go func() {
		defer close(requests)

		for _, raw := range r.Raw {
			// Add trailing line
			raw += "\n"

			if len(r.Payloads) > 0 {
				basePayloads := generators.LoadWordlists(r.Payloads)
				generatorFunc := generators.SniperGenerator
				switch r.attackType {
				case generators.PitchFork:
					generatorFunc = generators.PitchforkGenerator
				case generators.ClusterBomb:
					generatorFunc = generators.ClusterbombGenerator
				}

				for genValues := range generatorFunc(basePayloads) {
					compiledHTTP := r.handleRawWithPaylods(raw, baseURL, values, genValues)
					requests <- compiledHTTP
					if compiledHTTP.Error != nil {
						return
					}
				}
			} else {
				// otherwise continue with normal flow
				compiledHTTP := r.handleSimpleRaw(raw, baseURL, values)
				requests <- compiledHTTP
				if compiledHTTP.Error != nil {
					return
				}
			}
		}
	}()

	return requests, nil
}

func (r *HTTPRequest) handleSimpleRaw(raw string, baseURL string, values map[string]interface{}) *CompiledHTTP {
	// base request
	replacer := newReplacer(values)
	// Replace the dynamic variables in the request if any
	raw = replacer.Replace(raw)

	// Build a parsed request from raw
	parsedReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	// requests generated from http.ReadRequest have incorrect RequestURI, so they
	// cannot be used to perform another request directly, we need to generate a new one
	// with the new target url
	finalURL := fmt.Sprintf("%s%s", baseURL, parsedReq.URL)
	req, err := http.NewRequest(parsedReq.Method, finalURL, parsedReq.Body)
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	// copy headers
	req.Header = parsedReq.Header.Clone()

	request, err := r.fillRequest(req, values)
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	return &CompiledHTTP{Request: request, Error: nil, Meta: nil}
}

func (r *HTTPRequest) handleRawWithPaylods(raw string, baseURL string, values, genValues map[string]interface{}) *CompiledHTTP {
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
		if generators.StringContainsAnyMapItem(finValues, match) {
			expr := generators.TrimDelimiters(match)
			compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, generators.HelperFunctions())
			if err != nil {
				return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
			}
			result, err := compiled.Evaluate(finValues)
			if err != nil {
				return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
			}
			dynamicValues[expr] = result
		}
	}

	// replace dynamic values
	dynamicReplacer := newReplacer(dynamicValues)
	raw = dynamicReplacer.Replace(raw)

	// Build a parsed request from raw
	parsedReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	// Bug: http.ReadRequest does not process request body, so building it manually
	// need to read from first \n\n till end
	body := raw[strings.Index(raw, "\n\n"):]

	// requests generated from http.ReadRequest have incorrect RequestURI, so they
	// cannot be used to perform another request directly, we need to generate a new one
	// with the new target url
	finalURL := fmt.Sprintf("%s%s", baseURL, parsedReq.URL)
	req, err := http.NewRequest(parsedReq.Method, finalURL, strings.NewReader(body))
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	// copy headers
	req.Header = parsedReq.Header.Clone()

	request, err := r.fillRequest(req, values)
	if err != nil {
		return &CompiledHTTP{Request: nil, Error: err, Meta: nil}
	}

	return &CompiledHTTP{Request: request, Error: nil, Meta: genValues}
}

func (r *HTTPRequest) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	req.Header.Set("Connection", "close")
	req.Close = true

	// raw requests are left untouched
	if len(r.Raw) > 0 {
		return retryablehttp.FromRequest(req)
	}

	replacer := newReplacer(values)
	// Check if the user requested a request body
	if r.Body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(r.Body))
	}

	// Set the header values requested
	for header, value := range r.Headers {
		req.Header.Set(header, replacer.Replace(value))
	}

	// Set some headers only if the header wasn't supplied by the user
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")
	}

	if _, ok := req.Header["Accept"]; !ok {
		req.Header.Set("Accept", "*/*")
	}
	if _, ok := req.Header["Accept-Language"]; !ok {
		req.Header.Set("Accept-Language", "en")
	}

	return retryablehttp.FromRequest(req)
}

// CompiledHTTP contains Generated HTTP Request or error
type CompiledHTTP struct {
	Request *retryablehttp.Request
	Error   error
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
