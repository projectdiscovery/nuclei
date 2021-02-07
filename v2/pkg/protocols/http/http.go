package http

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Request contains a http request to be made from a template
type Request struct {
	ID string `yaml:"id"`

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
	// The minimum number of requests is determined by threads
	Race bool `yaml:"race"`
	// MaxSize is the maximum size of http response body to read in bytes.
	MaxSize int `yaml:"max-size"`

	// Fuzzing options for current client
	fuzzing.AnalyzerOptions `yaml:",inline"`
	CompiledAnalyzer        *fuzzing.AnalyzerOptions

	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	CompiledOperators   *operators.Operators

	options       *protocols.ExecuterOptions
	attackType    generators.Type
	totalRequests int
	customHeaders map[string]string
	generator     *generators.Generator // optional, only enabled when using payloads
	httpClient    *retryablehttp.Client
	rawhttpClient *rawhttp.Client
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	client, err := httpclientpool.Get(options.Options, &httpclientpool.Configuration{
		Threads:         r.Threads,
		MaxRedirects:    r.MaxRedirects,
		FollowRedirects: r.Redirects,
		CookieReuse:     r.CookieReuse,
	})
	if err != nil {
		return errors.Wrap(err, "could not get dns client")
	}
	r.customHeaders = make(map[string]string)
	r.httpClient = client
	r.options = options
	for _, option := range r.options.Options.CustomHeaders {
		parts := strings.SplitN(option, ":", 2)
		if len(parts) != 2 {
			continue
		}
		r.customHeaders[parts[0]] = strings.TrimSpace(parts[1])
	}

	if len(r.AnalyzerOptions.Append) > 0 || len(r.AnalyzerOptions.Replace) > 0 || len(r.AnalyzerOptions.BodyTemplate) > 0 {
		if err = r.AnalyzerOptions.Compile(); err != nil {
			return errors.Wrap(err, "could not compile fuzzing analyzer")
		}
		r.CompiledAnalyzer = &r.AnalyzerOptions
	}

	if r.Body != "" && !strings.Contains(r.Body, "\r\n") {
		r.Body = strings.ReplaceAll(r.Body, "\n", "\r\n")
	}
	if len(r.Raw) > 0 {
		for i, raw := range r.Raw {
			if !strings.Contains(raw, "\r\n") {
				r.Raw[i] = strings.ReplaceAll(raw, "\n", "\r\n")
			}
		}
		r.rawhttpClient = httpclientpool.GetRawHTTP()
	}
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}

	if len(r.Payloads) > 0 {
		attackType := r.AttackType
		if attackType == "" {
			attackType = "sniper"
		}
		r.attackType = generators.StringToType[attackType]

		// Resolve payload paths if they are files.
		for name, payload := range r.Payloads {
			switch pt := payload.(type) {
			case string:
				final, err := options.Catalogue.ResolvePath(pt, options.TemplatePath)
				if err != nil {
					return errors.Wrap(err, "could not read payload file")
				}
				r.Payloads[name] = final
			}
		}

		r.generator, err = generators.New(r.Payloads, r.attackType, r.options.TemplatePath)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}
	r.options = options
	r.totalRequests = r.Requests()
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	if r.generator != nil {
		payloadRequests := r.generator.NewIterator().Total() * len(r.Raw)
		return payloadRequests
	}
	if len(r.Raw) > 0 {
		requests := len(r.Raw)
		if requests == 1 && r.RaceNumberRequests != 0 {
			requests = requests * r.RaceNumberRequests
		}
		return requests
	}
	return len(r.Path)
}
