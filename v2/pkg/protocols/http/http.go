package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
)

// Request contains a http request to be made from a template
type Request struct {
	// Name is the name of the request
	Name string `yaml:"Name"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `yaml:"attack"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `yaml:"method"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `yaml:"body"`
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Raw contains raw requests
	Raw []string `yaml:"raw"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `yaml:"payloads"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers"`
	// RaceNumberRequests is the number of same request to send in race condition attack
	RaceNumberRequests int `yaml:"race_count"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `yaml:"max-redirects"`
	// PipelineConcurrentConnections is number of connections in pipelining
	PipelineConcurrentConnections int `yaml:"pipeline-concurrent-connections"`
	// PipelineRequestsPerConnection is number of requests in pipelining
	PipelineRequestsPerConnection int `yaml:"pipeline-requests-per-connection"`
	// Threads specifies number of threads for sending requests
	Threads int `yaml:"threads"`
	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `yaml:"cookie-reuse"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects"`
	// Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining (race conditions/billions requests)
	// All requests must be indempotent (GET/POST)
	Pipeline bool `yaml:"pipeline"`
	// Specify in order to skip request RFC normalization
	Unsafe bool `yaml:"unsafe"`
	// DisableAutoHostname Enable/Disable Host header for unsafe raw requests
	DisableAutoHostname bool `yaml:"disable-automatic-host-header"`
	// DisableAutoContentLength Enable/Disable Content-Length header for unsafe raw requests
	DisableAutoContentLength bool `yaml:"disable-automatic-content-length-header"`
	// Race determines if all the request have to be attempted at the same time
	// The minimum number fof requests is determined by threads
	Race bool `yaml:"race"`

	attackType generators.Type
	options    *protocols.ExecuterOptions
}
