package http

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"

	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Request contains a http request to be made from a template
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline" json:",inline"`
	// description: |
	//   Path contains the path/s for the HTTP requests. It supports variables
	//   as placeholders.
	// examples:
	//   - name: Some example path values
	//     value: >
	//       []string{"{{BaseURL}}", "{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions"}
	Path []string `yaml:"path,omitempty" json:"path,omitempty" jsonschema:"title=path(s) for the http request,description=Path(s) to send http requests to"`
	// description: |
	//   Raw contains HTTP Requests in Raw format.
	// examples:
	//   - name: Some example raw requests
	//     value: |
	//       []string{"GET /etc/passwd HTTP/1.1\nHost:\nContent-Length: 4", "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0\nContent-Length: 1\nConnection: close\n\necho\necho\ncat /etc/passwd 2>&1"}
	Raw []string `yaml:"raw,omitempty" json:"raw,omitempty" jsonschema:"http requests in raw format,description=HTTP Requests in Raw Format"`
	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id for the http request,description=ID for the HTTP Request"`
	// description: |
	//  Name is the optional name of the request.
	//
	//  If a name is specified, all the named request in a template can be matched upon
	//  in a combined manner allowing multi-request based matchers.
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=name for the http request,description=Optional name for the HTTP Request"`
	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	// values:
	//   - "batteringram"
	//   - "pitchfork"
	//   - "clusterbomb"
	AttackType generators.AttackTypeHolder `yaml:"attack,omitempty" json:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=batteringram,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Method is the HTTP Request Method.
	Method HTTPMethodTypeHolder `yaml:"method,omitempty" json:"method,omitempty" jsonschema:"title=method is the http request method,description=Method is the HTTP Request Method,enum=GET,enum=HEAD,enum=POST,enum=PUT,enum=DELETE,enum=CONNECT,enum=OPTIONS,enum=TRACE,enum=PATCH,enum=PURGE"`
	// description: |
	//   Body is an optional parameter which contains HTTP Request body.
	// examples:
	//   - name: Same Body for a Login POST request
	//     value: "\"username=test&password=test\""
	Body string `yaml:"body,omitempty" json:"body,omitempty" jsonschema:"title=body is the http request body,description=Body is an optional parameter which contains HTTP Request body"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the http request,description=Payloads contains any payloads for the current request"`

	// description: |
	//   Headers contains HTTP Headers to send with the request.
	// examples:
	//   - value: |
	//       map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "1", "Any-Header": "Any-Value"}
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty" jsonschema:"title=headers to send with the http request,description=Headers contains HTTP Headers to send with the request"`
	// description: |
	//   RaceCount is the number of times to send a request in Race Condition Attack.
	// examples:
	//   - name: Send a request 5 times
	//     value: "5"
	RaceNumberRequests int `yaml:"race_count,omitempty" json:"race_count,omitempty" jsonschema:"title=number of times to repeat request in race condition,description=Number of times to send a request in Race Condition Attack"`
	// description: |
	//   MaxRedirects is the maximum number of redirects that should be followed.
	// examples:
	//   - name: Follow up to 5 redirects
	//     value: "5"
	MaxRedirects int `yaml:"max-redirects,omitempty" json:"max-redirects,omitempty" jsonschema:"title=maximum number of redirects to follow,description=Maximum number of redirects that should be followed"`
	// description: |
	//   PipelineConcurrentConnections is number of connections to create during pipelining.
	// examples:
	//   - name: Create 40 concurrent connections
	//     value: 40
	PipelineConcurrentConnections int `yaml:"pipeline-concurrent-connections,omitempty" json:"pipeline-concurrent-connections,omitempty" jsonschema:"title=number of pipelining connections,description=Number of connections to create during pipelining"`
	// description: |
	//   PipelineRequestsPerConnection is number of requests to send per connection when pipelining.
	// examples:
	//   - name: Send 100 requests per pipeline connection
	//     value: 100
	PipelineRequestsPerConnection int `yaml:"pipeline-requests-per-connection,omitempty" json:"pipeline-requests-per-connection,omitempty" jsonschema:"title=number of requests to send per pipelining connections,description=Number of requests to send per connection when pipelining"`
	// description: |
	//   Threads specifies number of threads to use sending requests. This enables Connection Pooling.
	//
	//   Connection: Close attribute must not be used in request while using threads flag, otherwise
	//   pooling will fail and engine will continue to close connections after requests.
	// examples:
	//   - name: Send requests using 10 concurrent threads
	//     value: 10
	Threads int `yaml:"threads,omitempty" json:"threads,omitempty" jsonschema:"title=threads for sending requests,description=Threads specifies number of threads to use sending requests. This enables Connection Pooling"`
	// description: |
	//   MaxSize is the maximum size of http response body to read in bytes.
	// examples:
	//   - name: Read max 2048 bytes of the response
	//     value: 2048
	MaxSize int `yaml:"max-size,omitempty" json:"max-size,omitempty" jsonschema:"title=maximum http response body size,description=Maximum size of http response body to read in bytes"`

	// Fuzzing describes schema to fuzz http requests
	Fuzzing []*fuzz.Rule `yaml:"fuzzing,omitempty" json:"fuzzing,omitempty" jsonschema:"title=fuzzin rules for http fuzzing,description=Fuzzing describes rule schema to fuzz http requests"`
	// description: |
	//   Analyzer is an analyzer to use for matching the response.
	Analyzer *analyzers.AnalyzerTemplate `yaml:"analyzer,omitempty" json:"analyzer,omitempty" jsonschema:"title=analyzer for http request,description=Analyzer for HTTP Request"`

	CompiledOperators *operators.Operators `yaml:"-" json:"-"`

	options           *protocols.ExecutorOptions
	connConfiguration *httpclientpool.Configuration
	totalRequests     int
	customHeaders     map[string]string
	generator         *generators.PayloadGenerator // optional, only enabled when using payloads
	httpClient        *retryablehttp.Client
	rawhttpClient     *rawhttp.Client

	// description: |
	//   SelfContained specifies if the request is self-contained.
	SelfContained bool `yaml:"self-contained,omitempty" json:"self-contained,omitempty"`

	// description: |
	//   Signature is the request signature method
	// values:
	//   - "AWS"
	Signature SignatureTypeHolder `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=signature is the http request signature method,description=Signature is the HTTP Request signature Method,enum=AWS"`

	// description: |
	//   SkipSecretFile skips the authentication or authorization configured in the secret file.
	SkipSecretFile bool `yaml:"skip-secret-file,omitempty" json:"skip-secret-file,omitempty" jsonschema:"title=bypass secret file,description=Skips the authentication or authorization configured in the secret file"`

	// description: |
	//   CookieReuse is an optional setting that enables cookie reuse for
	//   all requests defined in raw section.
	// Deprecated: This is default now. Use disable-cookie to disable cookie reuse. cookie-reuse will be removed in future releases.
	CookieReuse bool `yaml:"cookie-reuse,omitempty" json:"cookie-reuse,omitempty" jsonschema:"title=optional cookie reuse enable,description=Optional setting that enables cookie reuse"`

	// description: |
	//   DisableCookie is an optional setting that disables cookie reuse
	DisableCookie bool `yaml:"disable-cookie,omitempty" json:"disable-cookie,omitempty" jsonschema:"title=optional disable cookie reuse,description=Optional setting that disables cookie reuse"`

	// description: |
	//   Enables force reading of the entire raw unsafe request body ignoring
	//   any specified content length headers.
	ForceReadAllBody bool `yaml:"read-all,omitempty" json:"read-all,omitempty" jsonschema:"title=force read all body,description=Enables force reading of entire unsafe http request body"`
	// description: |
	//   Redirects specifies whether redirects should be followed by the HTTP Client.
	//
	//   This can be used in conjunction with `max-redirects` to control the HTTP request redirects.
	Redirects bool `yaml:"redirects,omitempty" json:"redirects,omitempty" jsonschema:"title=follow http redirects,description=Specifies whether redirects should be followed by the HTTP Client"`
	// description: |
	//   Redirects specifies whether only redirects to the same host should be followed by the HTTP Client.
	//
	//   This can be used in conjunction with `max-redirects` to control the HTTP request redirects.
	HostRedirects bool `yaml:"host-redirects,omitempty" json:"host-redirects,omitempty" jsonschema:"title=follow same host http redirects,description=Specifies whether redirects to the same host should be followed by the HTTP Client"`
	// description: |
	//   Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining
	//
	//   All requests must be idempotent (GET/POST). This can be used for race conditions/billions requests.
	Pipeline bool `yaml:"pipeline,omitempty" json:"pipeline,omitempty" jsonschema:"title=perform HTTP 1.1 pipelining,description=Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining"`
	// description: |
	//   Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests.
	//
	//   This uses the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine to achieve complete
	//   control over the request, with no normalization performed by the client.
	Unsafe bool `yaml:"unsafe,omitempty" json:"unsafe,omitempty" jsonschema:"title=use rawhttp non-strict-rfc client,description=Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests"`
	// description: |
	//   Race determines if all the request have to be attempted at the same time (Race Condition)
	//
	//   The actual number of requests that will be sent is determined by the `race_count`  field.
	Race bool `yaml:"race,omitempty" json:"race,omitempty" jsonschema:"title=perform race-http request coordination attack,description=Race determines if all the request have to be attempted at the same time (Race Condition)"`
	// description: |
	//   ReqCondition automatically assigns numbers to requests and preserves their history.
	//
	//   This allows matching on them later for multi-request conditions.
	// Deprecated: request condition will be detected automatically (https://github.com/projectdiscovery/nuclei/issues/2393)
	ReqCondition bool `yaml:"req-condition,omitempty" json:"req-condition,omitempty" jsonschema:"title=preserve request history,description=Automatically assigns numbers to requests and preserves their history"`
	// description: |
	//   StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop the execution after a match is found"`
	// description: |
	//   SkipVariablesCheck skips the check for unresolved variables in request
	SkipVariablesCheck bool `yaml:"skip-variables-check,omitempty" json:"skip-variables-check,omitempty" jsonschema:"title=skip variable checks,description=Skips the check for unresolved variables in request"`
	// description: |
	//   IterateAll iterates all the values extracted from internal extractors
	// Deprecated: Use flow instead . iterate-all will be removed in future releases
	IterateAll bool `yaml:"iterate-all,omitempty" json:"iterate-all,omitempty" jsonschema:"title=iterate all the values,description=Iterates all the values extracted from internal extractors"`
	// description: |
	//   DigestAuthUsername specifies the username for digest authentication
	DigestAuthUsername string `yaml:"digest-username,omitempty" json:"digest-username,omitempty" jsonschema:"title=specifies the username for digest authentication,description=Optional parameter which specifies the username for digest auth"`
	// description: |
	//   DigestAuthPassword specifies the password for digest authentication
	DigestAuthPassword string `yaml:"digest-password,omitempty" json:"digest-password,omitempty" jsonschema:"title=specifies the password for digest authentication,description=Optional parameter which specifies the password for digest auth"`
	// description: |
	//  DisablePathAutomerge disables merging target url path with raw request path
	DisablePathAutomerge bool `yaml:"disable-path-automerge,omitempty" json:"disable-path-automerge,omitempty" jsonschema:"title=disable auto merging of path,description=Disable merging target url path with raw request path"`
	// description: |
	//   Fuzz PreCondition is matcher-like field to check if fuzzing should be performed on this request or not
	FuzzPreCondition []*matchers.Matcher `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty" jsonschema:"title=pre-condition for fuzzing/dast,description=PreCondition is matcher-like field to check if fuzzing should be performed on this request or not"`
	// description: |
	//  FuzzPreConditionOperator is the operator between multiple PreConditions for fuzzing Default is OR
	FuzzPreConditionOperator string                 `yaml:"pre-condition-operator,omitempty" json:"pre-condition-operator,omitempty" jsonschema:"title=condition between the filters,description=Operator to use between multiple per-conditions,enum=and,enum=or"`
	fuzzPreConditionOperator matchers.ConditionType `yaml:"-" json:"-"`
	// description: |
	//   GlobalMatchers marks matchers as static and applies globally to all result events from other templates
	GlobalMatchers bool `yaml:"global-matchers,omitempty" json:"global-matchers,omitempty" jsonschema:"title=global matchers,description=marks matchers as static and applies globally to all result events from other templates"`
}

func (e Request) JSONSchemaExtend(schema *jsonschema.Schema) {
	headersSchema, ok := schema.Properties.Get("headers")
	if !ok {
		return
	}
	headersSchema.PatternProperties = map[string]*jsonschema.Schema{
		".*": {
			OneOf: []*jsonschema.Schema{
				{
					Type: "string",
				},
				{
					Type: "integer",
				},
				{
					Type: "boolean",
				},
			},
		},
	}
	headersSchema.Ref = ""
}

// Options returns executer options for http request
func (r *Request) Options() *protocols.ExecutorOptions {
	return r.options
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":           "ID of the template executed",
	"template-info":         "Info Block of the template executed",
	"template-path":         "Path of the template executed",
	"host":                  "Host is the input to the template",
	"matched":               "Matched is the input which was matched upon",
	"type":                  "Type is the type of request made",
	"request":               "HTTP request made from the client",
	"response":              "HTTP response received from server",
	"status_code":           "Status Code received from the Server",
	"body":                  "HTTP response body received from server (default)",
	"content_length":        "HTTP Response content length",
	"header,all_headers":    "HTTP response headers",
	"duration":              "HTTP request time duration",
	"all":                   "HTTP response body + headers",
	"cookies_from_response": "HTTP response cookies in name:value format",
	"headers_from_response": "HTTP response headers in name:value format",
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

func (request *Request) isRaw() bool {
	return len(request.Raw) > 0
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	if err := request.validate(); err != nil {
		return errors.Wrap(err, "validation error")
	}

	connectionConfiguration := &httpclientpool.Configuration{
		Threads:       request.Threads,
		MaxRedirects:  request.MaxRedirects,
		NoTimeout:     false,
		DisableCookie: request.DisableCookie,
		Connection: &httpclientpool.ConnectionConfiguration{
			DisableKeepAlive: httputil.ShouldDisableKeepAlive(options.Options),
		},
		RedirectFlow: httpclientpool.DontFollowRedirect,
	}
	var customTimeout int
	if request.Analyzer != nil && request.Analyzer.Name == "time_delay" {
		var timeoutVal int
		if timeout, ok := request.Analyzer.Parameters["sleep_duration"]; ok {
			timeoutVal, _ = timeout.(int)
		} else {
			timeoutVal = 5
		}

		// Add 5x buffer to the timeout
		customTimeout = int(math.Ceil(float64(timeoutVal) * 5))
	}
	if customTimeout > 0 {
		connectionConfiguration.Connection.CustomMaxTimeout = time.Duration(customTimeout) * time.Second
	}

	if request.Redirects || options.Options.FollowRedirects {
		connectionConfiguration.RedirectFlow = httpclientpool.FollowAllRedirect
	}
	if request.HostRedirects || options.Options.FollowHostRedirects {
		connectionConfiguration.RedirectFlow = httpclientpool.FollowSameHostRedirect
	}

	// If we have request level timeout, ignore http client timeouts
	for _, req := range request.Raw {
		if reTimeoutAnnotation.MatchString(req) {
			connectionConfiguration.NoTimeout = true
		}
	}
	request.connConfiguration = connectionConfiguration

	client, err := httpclientpool.Get(options.Options, connectionConfiguration)
	if err != nil {
		return errors.Wrap(err, "could not get dns client")
	}
	request.customHeaders = make(map[string]string)
	request.httpClient = client
	request.options = options
	for _, option := range request.options.Options.CustomHeaders {
		parts := strings.SplitN(option, ":", 2)
		if len(parts) != 2 {
			continue
		}
		request.customHeaders[parts[0]] = strings.TrimSpace(parts[1])
	}

	if request.Body != "" && !strings.Contains(request.Body, "\r\n") {
		request.Body = strings.ReplaceAll(request.Body, "\n", "\r\n")
	}
	if len(request.Raw) > 0 {
		for i, raw := range request.Raw {
			if !strings.Contains(raw, "\r\n") {
				request.Raw[i] = strings.ReplaceAll(raw, "\n", "\r\n")
			}
		}
		request.rawhttpClient = httpclientpool.GetRawHTTP(options)
	}
	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if compileErr := compiled.Compile(); compileErr != nil {
			return errors.Wrap(compileErr, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}

	// === fuzzing filters ===== //

	if request.FuzzPreConditionOperator != "" {
		request.fuzzPreConditionOperator = matchers.ConditionTypes[request.FuzzPreConditionOperator]
	} else {
		request.fuzzPreConditionOperator = matchers.ORCondition
	}

	for _, filter := range request.FuzzPreCondition {
		if err := filter.CompileMatchers(); err != nil {
			return errors.Wrap(err, "could not compile matcher")
		}
	}

	if request.Analyzer != nil {
		if analyzer := analyzers.GetAnalyzer(request.Analyzer.Name); analyzer == nil {
			return errors.Errorf("analyzer %s not found", request.Analyzer.Name)
		}
	}

	// Resolve payload paths from vars if they exists
	for name, payload := range request.options.Options.Vars.AsMap() {
		payloadStr, ok := payload.(string)
		// check if inputs contains the payload
		var hasPayloadName bool
		// search for markers in all request parts
		var inputs []string
		inputs = append(inputs, request.Method.String(), request.Body)
		inputs = append(inputs, request.Raw...)
		for k, v := range request.customHeaders {
			inputs = append(inputs, fmt.Sprintf("%s: %s", k, v))
		}
		for k, v := range request.Headers {
			inputs = append(inputs, fmt.Sprintf("%s: %s", k, v))
		}

		for _, input := range inputs {
			if expressions.ContainsVariablesWithNames(map[string]interface{}{name: payload}, input) == nil {
				hasPayloadName = true
				break
			}
		}
		if ok && hasPayloadName && fileutil.FileExists(payloadStr) {
			if request.Payloads == nil {
				request.Payloads = make(map[string]interface{})
			}
			request.Payloads[name] = payloadStr
		}
	}

	// tries to drop unused payloads - by marshaling sections that might contain the payload
	unusedPayloads := make(map[string]struct{})
	requestSectionsToCheck := []interface{}{
		request.customHeaders, request.Headers, request.Matchers,
		request.Extractors, request.Body, request.Path, request.Raw, request.Fuzzing,
	}
	if requestSectionsToCheckData, err := json.Marshal(requestSectionsToCheck); err == nil {
		for payload := range request.Payloads {
			if bytes.Contains(requestSectionsToCheckData, []byte(payload)) {
				continue
			}
			unusedPayloads[payload] = struct{}{}
		}
	}
	for payload := range unusedPayloads {
		delete(request.Payloads, payload)
	}

	if len(request.Payloads) > 0 {
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, request.options.Catalog, request.options.Options.AttackType, request.options.Options)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}
	request.options = options
	request.totalRequests = request.Requests()

	if len(request.Fuzzing) > 0 {
		if request.Unsafe {
			return errors.New("cannot use unsafe with http fuzzing templates")
		}
		for _, rule := range request.Fuzzing {
			if fuzzingMode := options.Options.FuzzingMode; fuzzingMode != "" {
				rule.Mode = fuzzingMode
			}
			if fuzzingType := options.Options.FuzzingType; fuzzingType != "" {
				rule.Type = fuzzingType
			}
			if err := rule.Compile(request.generator, request.options); err != nil {
				return errors.Wrap(err, "could not compile fuzzing rule")
			}
		}
	}
	if len(request.Payloads) > 0 {
		// Due to a known issue (https://github.com/projectdiscovery/nuclei/issues/5015),
		// dynamic extractors cannot be used with payloads. To address this,
		// execution is handled by the standard engine without concurrency,
		// achieved by setting the thread count to 0.

		// this limitation will be removed once we have a better way to handle dynamic extractors with payloads
		hasMultipleRequests := false
		if len(request.Raw)+len(request.Path) > 1 {
			hasMultipleRequests = true
		}
		// look for dynamic extractor ( internal: true with named extractor)
		hasNamedInternalExtractor := false
		for _, extractor := range request.Extractors {
			if extractor.Internal && extractor.Name != "" {
				hasNamedInternalExtractor = true
				break
			}
		}
		if hasNamedInternalExtractor && hasMultipleRequests {
			stats.Increment(SetThreadToCountZero)
			request.Threads = 0
		} else {
			// specifically for http requests high concurrency and and threads will lead to memory exausthion, hence reduce the maximum parallelism
			if protocolstate.IsLowOnMemory() {
				request.Threads = protocolstate.GuardThreadsOrDefault(request.Threads)
			}
			request.Threads = options.GetThreadsForNPayloadRequests(request.Requests(), request.Threads)
		}
	}

	return nil
}

// RebuildGenerator rebuilds the generator for the request
func (request *Request) RebuildGenerator() error {
	generator, err := generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, request.options.Catalog, request.options.Options.AttackType, request.options.Options)
	if err != nil {
		return errors.Wrap(err, "could not parse payloads")
	}
	request.generator = generator
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	if request.generator != nil {
		payloadRequests := request.generator.NewIterator().Total()
		if len(request.Raw) > 0 {
			payloadRequests = payloadRequests * len(request.Raw)
		}
		if len(request.Path) > 0 {
			payloadRequests = payloadRequests * len(request.Path)
		}
		return payloadRequests
	}
	if len(request.Raw) > 0 {
		requests := len(request.Raw)
		if requests == 1 && request.RaceNumberRequests != 0 {
			requests *= request.RaceNumberRequests
		}
		return requests
	}
	return len(request.Path)
}

const (
	SetThreadToCountZero = "set-thread-count-to-zero"
)

func init() {
	stats.NewEntry(SetThreadToCountZero, "Setting thread count to 0 for %d templates, dynamic extractors are not supported with payloads yet")
}
