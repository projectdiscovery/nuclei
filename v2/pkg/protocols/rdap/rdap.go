package rdap

import (
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/openrdap/rdap"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the RDAP protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// description: |
	//   Address contains address for the request
	Host string `yaml:"host,omitempty" jsonschema:"title=host for the RDAP request,description=Host contains host for the request"`

	// description: |
	// 	 Optional RDAP server URL.
	//
	// 	 If present, specifies the RDAP server to execute the Request on.
	//   Otherwise, nil enables bootstrapping
	Server string `yaml:"server,omitempty" jsonschema:"title=server url to execute the RDAP request on,description=Server contains the server url to execute the RDAP request on"`
	// cache any variables that may be needed for operation.
	client          *rdap.Client
	options         *protocols.ExecuterOptions
	parsedServerURL *url.URL
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	var err error
	if request.Server != "" {
		request.parsedServerURL, err = url.Parse(request.Server)
		if err != nil {
			return errors.Wrap(err, "failed to parse server URL")
		}
	}

	request.options = options
	request.client = &rdap.Client{}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
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
func (request *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// build an rdap request
	rdapReq := rdap.NewAutoRequest(input)
	res, err := request.client.Do(rdapReq)
	if err != nil {
		return errors.Wrap(err, "could not make an rdap request")
	}
	gologger.Verbose().Msgf("Sent RDAP request to %s", input)
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("[%s] Dumped RDAP request for %s", request.options.TemplateID, input)
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
	data["host"] = input
	data["response"] = jsonDataString

	event := eventcreator.CreateEvent(request, data, request.options.Options.Debug || request.options.Options.DebugResponse)
	if request.options.Options.Debug || request.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped RDAP response for %s", request.options.TemplateID, input)
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
	return templateTypes.RDAPProtocol
}
