package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/post/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/post/matchers"
)

// Request is a http request structure parsed from a yaml file
type Request struct {
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
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `yaml:"max-redirects,omitempty"`

	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`

	// Raw contains raw requests
	Raw []string `yaml:"raw,omitempty"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `yaml:"attack,omitempty"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`
}
