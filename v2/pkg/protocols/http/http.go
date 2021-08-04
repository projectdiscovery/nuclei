package http

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Request contains a http request to be made from a template
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	// description: |
	//   Path contains the path/s for the HTTP requests. It supports variables
	//   as placeholders.
	// examples:
	//   - name: Some example path values
	//     value: >
	//       []string{"{{BaseURL}}", "{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions"}
	Path []string `yaml:"path,omitempty"`
	// description: |
	//   Raw contains HTTP Requests in Raw format.
	// examples:
	//   - name: Some example raw requests
	//     value: |
	//       []string{"GET /etc/passwd HTTP/1.1\nHost:\nContent-Length: 4", "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0\nContent-Length: 1\nConnection: close\n\necho\necho\ncat /etc/passwd 2>&1"}
	Raw []string `yaml:"raw,omitempty"`
	// ID is the ID of the request
	ID string `yaml:"id,omitempty"`
	// description: |
	//  Name is the optional name of the request.
	//
	//  If a name is specified, all the named request in a template can be matched upon
	//  in a combined manner allowing multirequest based matchers.
	Name string `yaml:"name,omitempty"`
	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	// values:
	//   - "sniper"
	//   - "pitchfork"
	//   - "clusterbomb"
	AttackType string `yaml:"attack,omitempty"`
	// description: |
	//   Method is the HTTP Request Method.
	// values:
	//   - "GET"
	//   - "POST"
	//   - "PUT"
	//   - "DELETE"
	Method string `yaml:"method,omitempty"`
	// description: |
	//   Body is an optional parameter which contains HTTP Request body.
	// examples:
	//   - name: Same Body for a Login POST request
	//     value: "\"username=test&password=test\""
	Body string `yaml:"body,omitempty"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	// examples:
	//   - name: A payload list for Tomcat Bruteforce
	//     value: >
	//       map[string]interface{}{
	//			"username": []string{"tomcat", "admin"},
	//	        "password": []string{"tomcat", "admin", "password"},
	//       }
	//   - name: A payload example of reading from file
	//     value: >
	//       map[string]interface{}{
	//	       "data": "helpers/payloads/command-injection.txt",
	//       }
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`
	// description: |
	//   Headers contains HTTP Headers to send with the request.
	// examples:
	//   - value: |
	//       map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "1", "Any-Header": "Any-Value"}
	Headers map[string]string `yaml:"headers,omitempty"`
	// description: |
	//   RaceCount is the number of times to send a request in Race Condition Attack.
	// examples:
	//   - name: Send a request 5 times
	//     value: "5"
	RaceNumberRequests int `yaml:"race_count,omitempty"`
	// description: |
	//   MaxRedirects is the maximum number of redirects that should be followed.
	// examples:
	//   - name: Follow upto 5 redirects
	//     value: "5"
	MaxRedirects int `yaml:"max-redirects,omitempty"`
	// description: |
	//   PipelineConcurrentConnections is number of connections to create during pipelining.
	// examples:
	//   - name: Create 40 concurrent connections
	//     value: 40
	PipelineConcurrentConnections int `yaml:"pipeline-concurrent-connections,omitempty"`
	// description: |
	//   PipelineRequestsPerConnection is number of requests to send per connection when pipelining.
	// examples:
	//   - name: Send 100 requests per pipeline connection
	//     value: 100
	PipelineRequestsPerConnection int `yaml:"pipeline-requests-per-connection,omitempty"`
	// description: |
	//   Threads specifies number of threads to use sending requests. This enables Connection Pooling.
	//
	//   Connection: Close attribute must not be used in request while using threads flag, otherwise
	//   pooling will fail and engine will continue to close connections after requests.
	// examples:
	//   - name: Send requests using 10 concurrent threads
	//     value: 10
	Threads int `yaml:"threads,omitempty"`

	// description: |
	//   MaxSize is the maximum size of http response body to read in bytes.
	// examples:
	//   - name: Read max 2048 bytes of the response
	//     value: 2048
	MaxSize int `yaml:"max-size,omitempty"`

	CompiledOperators *operators.Operators `yaml:"-"`

	options       *protocols.ExecuterOptions
	attackType    generators.Type
	totalRequests int
	customHeaders map[string]string
	generator     *generators.Generator // optional, only enabled when using payloads
	httpClient    *retryablehttp.Client
	rawhttpClient *rawhttp.Client

	// description: |
	//   CookieReuse is an optional setting that enables cookie reuse for
	//   all requests defined in raw section.
	CookieReuse bool `yaml:"cookie-reuse,omitempty"`
	// description: |
	//   Redirects specifies whether redirects should be followed by the HTTP Client.
	//
	//   This can be used in conjunction with `max-redirects` to control the HTTP request redirects.
	Redirects bool `yaml:"redirects,omitempty"`
	// description: |
	//   Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining
	//
	//   All requests must be indempotent (GET/POST). This can be used for race conditions/billions requests.
	Pipeline bool `yaml:"pipeline,omitempty"`
	// description: |
	//   Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests.
	//
	//   This uses the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine to achieve complete
	//   control over the request, with no normalization performed by the client.
	Unsafe bool `yaml:"unsafe,omitempty"`
	// description: |
	//   Race determines if all the request have to be attempted at the same time (Race Condition)
	//
	//   The actual number of requests that will be sent is determined by the `race_count`  field.
	Race bool `yaml:"race,omitempty"`
	// description: |
	//   ReqCondition automatically assigns numbers to requests and preserves their history.
	//
	//   This allows matching on them later for multi-request conditions.
	ReqCondition bool `yaml:"req-condition,omitempty"`
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

	if r.Body != "" && !strings.Contains(r.Body, "\r\n") {
		r.Body = strings.ReplaceAll(r.Body, "\n", "\r\n")
	}
	if len(r.Raw) > 0 {
		for i, raw := range r.Raw {
			if !strings.Contains(raw, "\r\n") {
				r.Raw[i] = strings.ReplaceAll(raw, "\n", "\r\n")
			}
		}
		r.rawhttpClient = httpclientpool.GetRawHTTP(options.Options)
	}
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if compileErr := compiled.Compile(); compileErr != nil {
			return errors.Wrap(compileErr, "could not compile operators")
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
			payloadStr, ok := payload.(string)
			if ok {
				final, resolveErr := options.Catalog.ResolvePath(payloadStr, options.TemplatePath)
				if resolveErr != nil {
					return errors.Wrap(resolveErr, "could not read payload file")
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
			requests *= r.RaceNumberRequests
		}
		return requests
	}
	return len(r.Path)
}
