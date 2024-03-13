package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/magodo/terraform-client-go/tfclient/typ"
	"github.com/pkg/errors"
	"github.com/zclconf/go-cty/cty"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID of the Request"`
	// description: |
	//   Engine type
	Provider string `yaml:"provider,omitempty" jsonschema:"title=terraform,description=terraform provider to use"`
	// description: |
	//   Source is the data source to query
	Source string `yaml:"source,omitempty" jsonschema:"title=source,description=Source is data source to query"`
	// description: |
	//   Engine Arguments
	Args []string `yaml:"args,omitempty" jsonschema:"title=args,description=Args"`

	options  *protocols.ExecutorOptions
	tfClient *TFProviderClient
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	if request.Provider != "aws" {
		return errors.New("temporarily only aws provider is allowed")
	}
	if !fileutil.FileExists(options.Options.PluginPath) {
		return errors.New("plugin not found pass it using -tf-plugin flag")
	}
	if request.Source == "" {
		return errors.New("resource cannot be empty, visit provider documentation for available data sources")
	}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		for _, matcher := range compiled.Matchers {
			// default matcher part for code protocol is response
			if matcher.Part == "" || matcher.Part == "body" {
				matcher.Part = "response"
			}
		}
		for _, extractor := range compiled.Extractors {
			// default extractor part for code protocol is response
			if extractor.Part == "" || extractor.Part == "body" {
				extractor.Part = "response"
			}
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
	return request.ID
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) (err error) {
	defer func() {
		// catch any panics just in case
		if r := recover(); r != nil {
			gologger.Error().Msgf("[%s] Panic occurred in code protocol: %s\n", request.options.TemplateID, r)
			err = fmt.Errorf("panic occurred: %s", r)
		}
	}()

	var interactshURLs []string

	// inject all template context values as gozero env allvars
	allvars := protocolutils.GenerateVariables(input.MetaInput.Input, false, nil)
	// add template context values if available
	if request.options.HasTemplateCtx(input.MetaInput) {
		allvars = generators.MergeMaps(allvars, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	variablesMap := request.options.Variables.Evaluate(allvars)
	// since we evaluate variables using allvars, give precedence to variablesMap
	allvars = generators.MergeMaps(allvars, variablesMap, optionVars, request.options.Constants)

	// get schema of given source
	attr := map[string]interface{}{}
	schema := request.tfClient.GetSchema(request.Source)
	if schema == nil {
		return fmt.Errorf("schema not found for %s", request.Source)
	}
	for name, info := range schema.Attributes {
		got := allvars[name]
		if got == nil && info.Required {
			return fmt.Errorf("required attribute %s not found", name)
		}
		attr[name] = got
	}

	timeout := 3 * request.options.Options.Timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// generate type from schema
	value, err := request.tfClient.GetTypedAttributes(ctx, request.Source, attr)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not get typed attributes")
	}

	// execute the data source
	resp, err := request.tfClient.Do(ctx, request.Source, value)
	if err != nil {
		resp = &typ.ReadDataSourceResponse{
			State: cty.StringVal(err.Error()),
		}
	}

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Cloud Protocol request variables: \n%s\n", vardump.DumpVariables(allvars))
	}

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("[%s] Dumped Executed Source Cloud for %v\n\n%v\n", request.options.TemplateID, input.MetaInput.Input, fmt.Sprintf("%s\n%s\n", request.Source, vardump.DumpVariables(attr)))
	}

	data := make(output.InternalEvent)
	// also include all request variables in result event
	for key, value := range allvars {
		data[key] = value
	}

	bin, err := request.tfClient.ParseResponse(resp, request.Source)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not parse response")
	}
	dataOutputString := string(bin) // this is always a json

	data["type"] = request.Type().String()
	data["response"] = dataOutputString // response contains filtered output (eg without trailing \n)
	data["input"] = input.MetaInput.Input
	data["template-path"] = request.options.TemplatePath
	data["template-id"] = request.options.TemplateID
	data["template-info"] = request.options.TemplateInfo

	// expose response variables in proto_var format
	// this is no-op if the template is not a multi protocol template
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, data)

	// add variables from template context before matching/extraction
	if request.options.HasTemplateCtx(input.MetaInput) {
		data = generators.MergeMaps(data, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}

	if request.options.Interactsh != nil {
		request.options.Interactsh.MakePlaceholders(interactshURLs, data)
	}

	// todo #1: interactsh async callback should be eliminated as it lead to ton of code duplication
	// todo #2: various structs InternalWrappedEvent, InternalEvent should be unwrapped and merged into minimal callbacks and a unique struct (eg. event?)
	event := eventcreator.CreateEvent(request, data, request.options.Options.Debug || request.options.Options.DebugResponse)
	if request.options.Interactsh != nil {
		event.UsesInteractsh = true
		request.options.Interactsh.RequestEvent(interactshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}

	if request.options.Options.Debug || request.options.Options.DebugResponse || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Cloud Execution for %s\n\n", request.options.TemplateID, input.MetaInput.Input)
		if request.options.Options.Debug || request.options.Options.DebugResponse {
			gologger.Debug().Msg(msg)
			gologger.Print().Msgf("%s\n\n", responsehighlighter.Highlight(event.OperatorsResult, dataOutputString, request.options.Options.NoColor, false))
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, dataOutputString))
		}
	}

	callback(event)

	return nil
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"type":    "Type is the type of request made",
	"host":    "Host is the input to the template",
	"matched": "Matched is the input which was matched upon",
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
	return templateTypes.CloudProtocol
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	fields := protocolutils.GetJsonFieldsFromURL(types.ToString(wrapped.InternalEvent["input"]))
	if types.ToString(wrapped.InternalEvent["ip"]) != "" {
		fields.Ip = types.ToString(wrapped.InternalEvent["ip"])
	}
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Matched:          types.ToString(wrapped.InternalEvent["input"]),
		Host:             fields.Host,
		Port:             fields.Port,
		Scheme:           fields.Scheme,
		URL:              fields.URL,
		IP:               fields.Ip,
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		TemplateEncoded:  request.options.EncodeTemplate(),
		Error:            types.ToString(wrapped.InternalEvent["error"]),
	}
	return data
}
