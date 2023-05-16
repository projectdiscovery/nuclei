package javascript

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/chroma/quick"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Request is a request for the javascript protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// description: |
	//   PreCondition is a condition which is evaluated before sending the request.
	PreCondition string `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty" jsonschema:"title=pre-condition for the request,description=PreCondition is a condition which is evaluated before sending the request"`
	// description: |
	//   Args contains the arguments to pass to the javascript code.
	Args map[string]interface{} `yaml:"args,omitempty" json:"args,omitempty"`
	// description: |
	//   Code contains code to execute for the javascript request.
	Code string `yaml:"code,omitempty" json:"code,omitempty" jsonschema:"title=code to execute in javascript,description=Executes inline javascript code for the request"`
	// description: |
	//   Output captures the output of the javascript code
	//   and makes it available for matching and extraction.
	Output bool `yaml:"output,omitempty" json:"output,omitempty" jsonschema:"title=capture output of the javascript code,description=Captures output of the javascript code"`

	// description: |
	//   StopAtFirstMatch stops processing the request at first match.
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop the execution after a match is found"`
	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	AttackType generators.AttackTypeHolder `yaml:"attack,omitempty" json:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=sniper,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the webosocket request,description=Payloads contains any payloads for the current request"`

	generator *generators.PayloadGenerator

	// cache any variables that may be needed for operation.
	compiler *compiler.Compiler
	options  *protocols.ExecuterOptions
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	request.options = options

	request.compiler = options.Compiler

	var err error
	if len(request.Payloads) > 0 {
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, request.options.Options.Sandbox, options.Catalog, options.Options.AttackType)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not compile operators got %v", err)
		}
		request.CompiledOperators = compiled
	}
	return nil
}

// Options returns executer options for http request
func (r *Request) Options() *protocols.ExecuterOptions {
	return r.options
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
	hostPort, err := getAddress(input.MetaInput.Input)
	if err != nil {
		return err
	}
	hostname, port, _ := net.SplitHostPort(hostPort)
	if hostname == "" {
		hostname = hostPort
	}

	requestOptions := request.options
	payloadValues := generators.BuildPayloadFromOptions(request.options.Options)
	for k, v := range dynamicValues {
		payloadValues[k] = v
	}

	payloadValues["Hostname"] = hostPort
	payloadValues["Host"] = hostname
	payloadValues["Port"] = port

	hostnameVariables := protocolutils.GenerateDNSVariables(hostname)
	values := generators.MergeMaps(payloadValues, hostnameVariables)
	variablesMap := request.options.Variables.Evaluate(values)
	payloadValues = generators.MergeMaps(variablesMap, payloadValues)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(payloadValues))
	}

	if request.PreCondition != "" {
		payloads := generators.MergeMaps(payloadValues, previous)

		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Debug().Msgf("[%s] Executing Precondition for request\n", request.TemplateID)
			var highlightFormatter = "terminal256"
			if requestOptions.Options.NoColor {
				highlightFormatter = "text"
			}
			quick.Highlight(os.Stdout, beautifyJavascript(request.PreCondition), "javascript", highlightFormatter, "monokai")
			fmt.Println("")
		}

		argsCopy, err := request.getArgsCopy(input, payloads, requestOptions)
		if err != nil {
			return err
		}

		result, err := request.compiler.Execute(request.PreCondition, argsCopy)
		if err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not execute pre-condition: %s", err)
		}
		if !result.GetSuccess() {
			gologger.Warning().Msgf("[%s] Precondition for request %s was not satisfied\n", request.TemplateID, request.PreCondition)
			return nil
		}
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Debug().Msgf("[%s] Precondition for request was satisfied\n", request.TemplateID)
		}
	}

	var gotMatches bool
	if request.generator != nil {
		iterator := request.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				return nil
			}

			if err := request.executeRequestWithPayloads(hostPort, input, hostname, value, payloadValues, func(result *output.InternalWrappedEvent) {
				if result.OperatorsResult != nil && result.OperatorsResult.Matched {
					gotMatches = true
				}
				callback(result)
			}, requestOptions); err != nil {
				gologger.Warning().Msgf("Could not execute request: %s\n", err)
				continue
			}
			// If this was a match, and we want to stop at first match, skip all further requests.
			shouldStopAtFirstMatch := request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch
			if shouldStopAtFirstMatch && gotMatches {
				return nil
			}
		}
	}
	return request.executeRequestWithPayloads(hostPort, input, hostname, nil, payloadValues, callback, requestOptions)
}

func (request *Request) executeRequestWithPayloads(hostPort string, input *contextargs.Context, hostname string, payload map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback, requestOptions *protocols.ExecuterOptions) error {
	payloadValues := generators.MergeMaps(payload, previous)
	argsCopy, err := request.getArgsCopy(input, payloadValues, requestOptions)
	if err != nil {
		return err
	}

	results, err := request.compiler.ExecuteWithOptions(request.Code, argsCopy, &compiler.ExecuteOptions{
		Pool:          false,
		CaptureOutput: request.Output,
	})
	if err != nil {
		return errorutil.NewWithTag(request.TemplateID, "could not execute javascript code: %s", err)
	}

	requestOptions.Output.Request(requestOptions.TemplateID, hostPort, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent Javascript request to %s", hostPort)

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Javascript request for %s:\nVariables: %+v\n\n", requestOptions.TemplateID, input.MetaInput.Input, argsCopy)

		if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
			gologger.Debug().Str("address", input.MetaInput.Input).Msg(msg)
			var highlightFormatter = "terminal256"
			if requestOptions.Options.NoColor {
				highlightFormatter = "text"
			}
			quick.Highlight(os.Stdout, beautifyJavascript(request.Code), "javascript", highlightFormatter, "monokai")
			fmt.Println("")
		}
		if requestOptions.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), msg)
		}
	}

	data := make(map[string]interface{})
	for k, v := range payloadValues {
		data[k] = v
	}
	data["type"] = request.Type().String()
	for k, v := range results {
		data[k] = v
	}
	data["request"] = beautifyJavascript(request.Code)
	data["response"] = results
	data["host"] = input.MetaInput.Input
	data["matched"] = hostPort
	data["template-path"] = requestOptions.TemplatePath
	data["template-id"] = requestOptions.TemplateID
	data["template-info"] = requestOptions.TemplateInfo
	if request.StopAtFirstMatch || request.options.StopAtFirstMatch {
		data["stop-at-first-match"] = true
	}

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Javascript response for %s:\n%+v", requestOptions.TemplateID, input.MetaInput.Input, results)
		if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
			gologger.Debug().Str("address", input.MetaInput.Input).Msg(msg)
		}
		if requestOptions.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), msg)
		}
	}

	event := eventcreator.CreateEventWithAdditionalOptions(request, data, requestOptions.Options.Debug || requestOptions.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
		internalWrappedEvent.OperatorsResult.PayloadValues = payload
	})
	callback(event)
	return nil
}

func (request *Request) getArgsCopy(input *contextargs.Context, payloadValues map[string]interface{}, requestOptions *protocols.ExecuterOptions) (map[string]interface{}, error) {
	// Template args from payloads
	argsCopy := make(map[string]interface{})
	for k, v := range request.Args {
		if vVal, ok := v.(string); ok && strings.Contains(vVal, "{") {
			finalAddress, dataErr := expressions.Evaluate(vVal, payloadValues)
			if dataErr != nil {
				requestOptions.Output.Request(requestOptions.TemplateID, input.MetaInput.Input, request.Type().String(), dataErr)
				requestOptions.Progress.IncrementFailedRequestsBy(1)
				return nil, errors.Wrap(dataErr, "could not evaluate template expressions")
			}
			argsCopy[k] = finalAddress
		} else {
			argsCopy[k] = v
		}
	}
	return argsCopy, nil
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"type":     "Type is the type of request made",
	"response": "Javascript protocol result response",
	"host":     "Host is the input to the template",
	"matched":  "Matched is the input which was matched upon",
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	urlx, err := urlutil.Parse(toTest)
	if err != nil {
		// use given input instead of url parsing failure
		return toTest, nil
	}
	return urlx.Host, nil
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

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.JavascriptProtocol
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["response"]),
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
	}
	return data
}

func beautifyJavascript(code string) string {
	opts := jsbeautifier.DefaultOptions()
	beautified, err := jsbeautifier.Beautify(&code, opts)
	if err != nil {
		return code
	}
	return beautified
}
