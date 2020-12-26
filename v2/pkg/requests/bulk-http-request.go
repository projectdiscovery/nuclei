package requests

import (
	"regexp"

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
