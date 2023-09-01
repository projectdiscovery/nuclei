package javascript

import (
	"bytes"
	"fmt"
	"net"
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
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
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
	// ID is request id in that protocol
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID of the Request"`

	// description: |
	//   PreCondition is a condition which is evaluated before sending the request.
	PreCondition string `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty" jsonschema:"title=pre-condition for the request,description=PreCondition is a condition which is evaluated before sending the request"`
	// description: |
	//   PreConditionExports is a list of variables to export from the pre-condition.
	PreConditionExports []string `yaml:"pre-condition-exports,omitempty" json:"pre-condition-exports,omitempty" jsonschema:"title=pre-condition exports for the request,description=PreConditionExports is a list of variables to export from the pre-condition"`

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
	options *protocols.ExecutorOptions `yaml:"-" json:"-"`
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	var err error
	if len(request.Payloads) > 0 {
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, options.Catalog, options.Options.AttackType, options.Options)
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
func (r *Request) Options() *protocols.ExecutorOptions {
	return r.options
}

// Requests returns the total number of requests the rule will perform
func (request *Request) Requests() int {
	return 1
}

// GetID returns the ID for the request if any.
func (request *Request) GetID() string {
	return request.ID
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
	templateCtx := request.options.GetTemplateCtx(input.MetaInput)

	payloadValues := generators.BuildPayloadFromOptions(request.options.Options)
	for k, v := range dynamicValues {
		payloadValues[k] = v
	}

	payloadValues["Hostname"] = hostPort
	payloadValues["Host"] = hostname
	payloadValues["Port"] = port

	hostnameVariables := protocolutils.GenerateDNSVariables(hostname)
	values := generators.MergeMaps(payloadValues, hostnameVariables, request.options.Constants, templateCtx.GetAll())
	variablesMap := request.options.Variables.Evaluate(values)
	payloadValues = generators.MergeMaps(variablesMap, payloadValues, request.options.Constants, hostnameVariables)

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
			var buff bytes.Buffer
			quick.Highlight(&buff, beautifyJavascript(request.PreCondition), "javascript", highlightFormatter, "monokai")
			gologger.DefaultLogger.Print().Msgf("%v", buff.String())
		}

		argsCopy, err := request.getArgsCopy(input, payloads, requestOptions, true)
		if err != nil {
			return err
		}
		argsCopy.TemplateCtx = templateCtx.GetAll()

		result, err := request.options.JsCompiler.ExecuteWithOptions(request.PreCondition, argsCopy, &compiler.ExecuteOptions{
			CaptureVariables: request.PreConditionExports,
		})
		if err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not execute pre-condition: %s", err)
		}
		if !result.GetSuccess() && len(request.PreConditionExports) == 0 {
			gologger.Warning().Msgf("[%s] Precondition for request %s was not satisfied\n", request.TemplateID, request.PreCondition)
			return nil
		}
		if len(request.PreConditionExports) > 0 {
			for _, export := range request.PreConditionExports {
				if _, ok := result[export]; !ok {
					gologger.Warning().Msgf("[%s] Precondition for request %s was not satisfied\n", request.TemplateID, request.PreCondition)
					return nil
				} else {
					payloadValues[export] = result[export]
					templateCtx.Set(export, result[export])
				}
			}
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
				return nil
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

func (request *Request) executeRequestWithPayloads(hostPort string, input *contextargs.Context, hostname string, payload map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback, requestOptions *protocols.ExecutorOptions) error {
	payloadValues := generators.MergeMaps(payload, previous)
	argsCopy, err := request.getArgsCopy(input, payloadValues, requestOptions, false)
	if err != nil {
		return err
	}
	argsCopy.TemplateCtx = request.options.GetTemplateCtx(input.MetaInput).GetAll()

	var requestData = []byte(request.Code)
	var interactshURLs []string
	if request.options.Interactsh != nil {
		var transformedData string
		transformedData, interactshURLs = request.options.Interactsh.Replace(string(request.Code), []string{})
		requestData = []byte(transformedData)
	}

	results, err := request.options.JsCompiler.ExecuteWithOptions(string(requestData), argsCopy, &compiler.ExecuteOptions{
		Pool:          false,
		CaptureOutput: request.Output,
	})
	if err != nil {
		// shouldn't fail even if it returned error instead create a failure event
		results = compiler.ExecuteResult{"success": false, "error": err.Error()}
	}

	requestOptions.Output.Request(requestOptions.TemplateID, hostPort, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent Javascript request to %s", hostPort)

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Javascript request for %s:\nVariables: %+v", requestOptions.TemplateID, input.MetaInput.Input, argsCopy)

		if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
			gologger.Debug().Str("address", input.MetaInput.Input).Msg(msg)
			var highlightFormatter = "terminal256"
			if requestOptions.Options.NoColor {
				highlightFormatter = "text"
			}
			var buff bytes.Buffer
			quick.Highlight(&buff, beautifyJavascript(request.Code), "javascript", highlightFormatter, "monokai")
			gologger.DefaultLogger.Print().Msgf("%v", buff.String())
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
	if len(results) > 0 {
		data["response"] = results
	}
	data["host"] = input.MetaInput.Input
	data["matched"] = hostPort
	data["template-path"] = requestOptions.TemplatePath
	data["template-id"] = requestOptions.TemplateID
	data["template-info"] = requestOptions.TemplateInfo
	if request.StopAtFirstMatch || request.options.StopAtFirstMatch {
		data["stop-at-first-match"] = true
	}

	// add and get values from templatectx
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.GetID(), data)
	data = generators.MergeMaps(data, request.options.GetTemplateCtx(input.MetaInput).GetAll())

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Javascript response for %s:\n%+v", requestOptions.TemplateID, input.MetaInput.Input, results)
		if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
			gologger.Debug().Str("address", input.MetaInput.Input).Msg(msg)
		}
		if requestOptions.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), msg)
		}
	}

	if w, ok := data["error"]; ok && w != nil {
		event := eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(data, payloadValues), request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
			wrappedEvent.OperatorsResult.PayloadValues = payload
		})
		callback(event)
		return err
	}

	if request.options.Interactsh != nil {
		request.options.Interactsh.MakePlaceholders(interactshURLs, data)
	}

	var event *output.InternalWrappedEvent
	if len(interactshURLs) == 0 {
		event = eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(data, payloadValues), request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
			wrappedEvent.OperatorsResult.PayloadValues = payload
		})
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: data, UsesInteractsh: true}
		request.options.Interactsh.RequestEvent(interactshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}
	return nil
}

func (request *Request) getArgsCopy(input *contextargs.Context, payloadValues map[string]interface{}, requestOptions *protocols.ExecutorOptions, ignoreErrors bool) (*compiler.ExecuteArgs, error) {
	// Template args from payloads
	argsCopy := make(map[string]interface{})
mainLoop:
	for k, v := range request.Args {
		if vVal, ok := v.(string); ok && strings.Contains(vVal, "{") {
			finalAddress, dataErr := expressions.Evaluate(vVal, payloadValues)
			if dataErr != nil {
				requestOptions.Output.Request(requestOptions.TemplateID, input.MetaInput.Input, request.Type().String(), dataErr)
				requestOptions.Progress.IncrementFailedRequestsBy(1)
				return nil, errors.Wrap(dataErr, "could not evaluate template expressions")
			}
			if finalAddress == vVal && ignoreErrors {
				argsCopy[k] = ""
				continue mainLoop
			}
			argsCopy[k] = finalAddress
		} else {
			argsCopy[k] = v
		}
	}
	return &compiler.ExecuteArgs{Args: argsCopy}, nil
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
