package requests

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/rawhttp"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

const (
	two   = 2
	three = 3
)

var urlWithPortRgx = regexp.MustCompile(`{{BaseURL}}:(\d+)`)

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
