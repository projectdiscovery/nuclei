package requests

import (
	"context"
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

const (
	two   = 2
	three = 3
)

// BulkHTTPRequest contains a request to be made from a template
type BulkHTTPRequest struct {
	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `yaml:"cookie-reuse,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool   `yaml:"redirects,omitempty"`
	Name      string `yaml:"Name,omitempty"`
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

// Returns the total number of requests the YAML rule will perform
func (r *BulkHTTPRequest) GetRequestCount() int64 {
	return int64(len(r.Raw) | len(r.Path))
}

func (r *BulkHTTPRequest) MakeHTTPRequest(ctx context.Context, baseURL string, dynamicValues map[string]interface{}, data string) (*HTTPRequest, error) {
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

func (r *BulkHTTPRequest) InitGenerator() {
	r.gsfm = NewGeneratorFSM(r.attackType, r.Payloads, r.Path, r.Raw)
}

func (r *BulkHTTPRequest) CreateGenerator(reqURL string) {
	r.gsfm.Add(reqURL)
}

func (r *BulkHTTPRequest) HasGenerator(reqURL string) bool {
	return r.gsfm.Has(reqURL)
}

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

		return r.handleRawWithPaylods(ctx, data, baseURL, values, r.gsfm.Value(baseURL))
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

	req, err := http.NewRequestWithContext(ctx, compiledRequest.Method, compiledRequest.FullURL, strings.NewReader(compiledRequest.Data))
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

	return &HTTPRequest{Request: request, Meta: genValues}, nil
}

type HTTPRequest struct {
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

func (r *BulkHTTPRequest) Next(reqURL string) bool {
	return r.gsfm.Next(reqURL)
}
func (r *BulkHTTPRequest) Position(reqURL string) int {
	return r.gsfm.Position(reqURL)
}

func (r *BulkHTTPRequest) Reset(reqURL string) {
	r.gsfm.Reset(reqURL)
}

func (r *BulkHTTPRequest) Current(reqURL string) string {
	return r.gsfm.Current(reqURL)
}

func (r *BulkHTTPRequest) Total() int {
	return len(r.Path) + len(r.Raw)
}

func (r *BulkHTTPRequest) Increment(reqURL string) {
	r.gsfm.Increment(reqURL)
}
