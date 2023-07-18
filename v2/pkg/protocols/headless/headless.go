package headless

import (
	"github.com/corpix/uarand"
	"github.com/pkg/errors"

	useragent "github.com/projectdiscovery/nuclei/v2/pkg/model/types/userAgent"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Request contains a Headless protocol request to be made from a template
type Request struct {
	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=Optional ID of the headless request"`

	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	AttackType generators.AttackTypeHolder `yaml:"attack,omitempty" json:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=batteringram,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the headless request,description=Payloads contains any payloads for the current request"`

	// description: |
	//   Steps is the list of actions to run for headless request
	Steps []*engine.Action `yaml:"steps,omitempty" json:"steps,omitempty" jsonschema:"title=list of actions for headless request,description=List of actions to run for headless request"`

	// descriptions: |
	// 	 User-Agent is the type of user-agent to use for the request.
	UserAgent useragent.UserAgentHolder `yaml:"user_agent,omitempty" json:"user_agent,omitempty" jsonschema:"title=user agent for the headless request,description=User agent for the headless request"`

	// description: |
	// 	 If UserAgent is set to custom, customUserAgent is the custom user-agent to use for the request.
	CustomUserAgent   string `yaml:"custom_user_agent,omitempty" json:"custom_user_agent,omitempty" jsonschema:"title=custom user agent for the headless request,description=Custom user agent for the headless request"`
	compiledUserAgent string
	// description: |
	//   StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop the execution after a match is found"`

	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// cache any variables that may be needed for operation.
	options   *protocols.ExecutorOptions
	generator *generators.PayloadGenerator

	// Fuzzing describes schema to fuzz headless requests
	Fuzzing []*fuzz.Rule `yaml:"fuzzing,omitempty" json:"fuzzing,omitempty" jsonschema:"title=fuzzin rules for http fuzzing,description=Fuzzing describes rule schema to fuzz headless requests"`

	// description: |
	//   CookieReuse is an optional setting that enables cookie reuse
	CookieReuse bool `yaml:"cookie-reuse,omitempty" json:"cookie-reuse,omitempty" jsonschema:"title=optional cookie reuse enable,description=Optional setting that enables cookie reuse"`
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":    "ID of the template executed",
	"template-info":  "Info Block of the template executed",
	"template-path":  "Path of the template executed",
	"host":           "Host is the input to the template",
	"matched":        "Matched is the input which was matched upon",
	"type":           "Type is the type of request made",
	"req":            "Headless request made from the client",
	"resp,body,data": "Headless response received from client (default)",
}

// Step is a headless protocol request step.
type Step struct {
	// Action is the headless action to execute for the script
	Action string `yaml:"action"`
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	// TODO: logic similar to network + http => probably can be refactored
	// Resolve payload paths from vars if they exists
	for name, payload := range options.Options.Vars.AsMap() {
		payloadStr, ok := payload.(string)
		// check if inputs contains the payload
		if ok && fileutil.FileExists(payloadStr) {
			if request.Payloads == nil {
				request.Payloads = make(map[string]interface{})
			}
			request.Payloads[name] = payloadStr
		}
	}

	if len(request.Payloads) > 0 {
		var err error
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, options.TemplatePath, options.Options.AllowLocalFileAccess, options.Catalog, options.Options.AttackType)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}

	// Compile User-Agent
	switch request.UserAgent.Value {
	case useragent.Off:
		request.compiledUserAgent = " "
	case useragent.Default:
		request.compiledUserAgent = ""
	case useragent.Custom:
		if request.CustomUserAgent == "" {
			return errors.New("please set custom_user_agent in the template")
		}
		request.compiledUserAgent = request.CustomUserAgent
	case useragent.Random:
		request.compiledUserAgent = uarand.GetRandom()
	}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	request.options = options

	if len(request.Fuzzing) > 0 {
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

	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 1
}
