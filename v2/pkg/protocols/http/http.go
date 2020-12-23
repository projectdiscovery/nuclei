package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
)

// Request contains a http request to be made from a template
type Request struct {
	// Number of same request to send in race condition attack
	RaceNumberRequests int `yaml:"race_count,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects                  int `yaml:"max-redirects,omitempty"`
	PipelineConcurrentConnections int `yaml:"pipeline-concurrent-connections,omitempty"`
	PipelineRequestsPerConnection int `yaml:"pipeline-requests-per-connection,omitempty"`
	Threads                       int `yaml:"threads,omitempty"`
	// attackType is internal attack type
	attackType generators.Type
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
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
	// Name is the name of the request
	Name string `yaml:"Name,omitempty"`
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
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Raw contains raw requests
	Raw []string `yaml:"raw,omitempty"`
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty"`
}
