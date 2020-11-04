package requests

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
)

// NetworkRequest contains a request to be made from a template
type NetworkRequest struct {
	// Address is the address to send requests to (host:port combos generally)
	Address     string `yaml:"address"`
	addressPort string
	// Payload is the payload to send for the network request
	Payload string `yaml:"payload"`
	// ReadSize is the size of response to read (1024 if not provided by default)
	ReadSize int `yaml:"read-size"`

	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
}

// GeneratePort generates the port for a network request
func (r *NetworkRequest) GeneratePort() {
	r.addressPort = strings.TrimPrefix(r.Address, "{{BaseURL}}:")
}

// GetPort returns the port for a network request
func (r *NetworkRequest) GetPort() string {
	return r.addressPort
}

// GetMatchersCondition returns the condition for the matcher
func (r *NetworkRequest) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// SetMatchersCondition sets the condition for the matcher
func (r *NetworkRequest) SetMatchersCondition(condition matchers.ConditionType) {
	r.matchersCondition = condition
}

// GetRequestCount returns the total number of requests the YAML rule will perform
func (r *NetworkRequest) GetRequestCount() int64 {
	return 1
}
