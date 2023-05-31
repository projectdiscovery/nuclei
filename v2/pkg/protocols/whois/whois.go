package whois

import (
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/rdap"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/whois/rdapclientpool"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the WHOIS protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// description: |
	//   Query contains query for the request
	Query string `yaml:"query,omitempty" json:"query,omitempty" jsonschema:"title=query for the WHOIS request,description=Query contains query for the request"`

	// description: |
	// 	 Optional WHOIS server URL.
	//
	// 	 If present, specifies the WHOIS server to execute the Request on.
	//   Otherwise, nil enables bootstrapping
	Server string `yaml:"server,omitempty" json:"server,omitempty" jsonschema:"title=server url to execute the WHOIS request on,description=Server contains the server url to execute the WHOIS request on"`
	// cache any variables that may be needed for operation.
	client          *rdap.Client
	options         *protocols.ExecutorOptions
	parsedServerURL *url.URL
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	var err error
	if request.Server != "" {
		request.parsedServerURL, err = url.Parse(request.Server)
		if err != nil {
			return errors.Wrap(err, "failed to parse server URL")
		}
	}

	request.options = options
	request.client, _ = rdapclientpool.Get(options.Options, nil)

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (request *Request) Requests() int {
	return 1
}

// GetID returns the ID for the request if any.
func (request *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// generate variables
	defaultVars := protocolutils.GenerateVariables(input.MetaInput.Input, false, nil)
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	vars := request.options.Variables.Evaluate(generators.MergeMaps(defaultVars, optionVars, dynamicValues))

	variables := generators.MergeMaps(vars, defaultVars, optionVars, dynamicValues, request.options.Constants)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(variables))
	}

	// and replace placeholders
	query := replacer.Replace(request.Query, variables)
	// build an rdap request
	rdapReq := rdap.NewAutoRequest(query)
	rdapReq.Server = request.parsedServerURL
	res, err := request.client.Do(rdapReq)
	if err != nil {
		return errors.Wrap(err, "could not make whois request")
	}
	gologger.Verbose().Msgf("Sent WHOIS request to %s", query)
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("[%s] Dumped WHOIS request for %s", request.options.TemplateID, query)
	}

	data := make(map[string]interface{})
	var response interface{}
	switch rdapReq.Type {
	case rdap.DomainRequest:
		// convert the rdap response to a whois style response (for domain request type only)
		whoisResp := res.ToWhoisStyleResponse()
		for k, v := range whoisResp.Data {
			data[strings.ToLower(k)] = strings.Join(v, ",")
		}
		response = whoisResp
	default:
		response = res.Object
	}
	jsonData, _ := jsoniter.Marshal(response)
	jsonDataString := string(jsonData)

	data["type"] = request.Type().String()
	data["host"] = query
	data["response"] = jsonDataString

	event := eventcreator.CreateEvent(request, data, request.options.Options.Debug || request.options.Options.DebugResponse)
	if request.options.Options.Debug || request.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped WHOIS response for %s", request.options.TemplateID, query)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, jsonDataString, request.options.Options.NoColor, false))
	}

	callback(event)
	return nil
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["response"]),
	}
	return data
}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.WHOISProtocol
}
