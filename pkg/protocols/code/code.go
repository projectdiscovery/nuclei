package code

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
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
	Engine []string `yaml:"engine,omitempty" jsonschema:"title=engine,description=Engine,enum=python,enum=powershell,enum=command"`
	// description: |
	//   Engine Arguments
	Args []string `yaml:"args,omitempty" jsonschema:"title=args,description=Args"`
	// description: |
	//   Pattern preferred for file name
	Pattern string `yaml:"pattern,omitempty" jsonschema:"title=pattern,description=Pattern"`
	// description: |
	//   Source File/Snippet
	Source string `yaml:"source,omitempty" jsonschema:"title=source file/snippet,description=Source snippet"`

	options *protocols.ExecutorOptions
	gozero  *gozero.Gozero
	src     *gozero.Source
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	gozeroOptions := &gozero.Options{
		Engines:                  request.Engine,
		Args:                     request.Args,
		EarlyCloseFileDescriptor: true,
	}
	engine, err := gozero.New(gozeroOptions)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("[%s] engines '%s' not available on host", options.TemplateID, strings.Join(request.Engine, ","))
	}
	request.gozero = engine

	var src *gozero.Source

	src, err = gozero.NewSourceWithString(request.Source, request.Pattern)
	if err != nil {
		return err
	}
	request.src = src

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
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	metaSrc, err := gozero.NewSourceWithString(input.MetaInput.Input, "")
	if err != nil {
		return err
	}
	defer func() {
		if err := metaSrc.Cleanup(); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}()

	var interactshURLs []string

	// inject all template context values as gozero env variables
	variables := protocolutils.GenerateVariables(input.MetaInput.Input, false, nil)
	// add template context values
	variables = generators.MergeMaps(variables, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	variablesMap := request.options.Variables.Evaluate(variables)
	variables = generators.MergeMaps(variablesMap, variables, optionVars, request.options.Constants)
	for name, value := range variables {
		v := fmt.Sprint(value)
		v, interactshURLs = request.options.Interactsh.Replace(v, interactshURLs)
		metaSrc.AddVariable(gozerotypes.Variable{Name: name, Value: v})
	}
	gOutput, err := request.gozero.Eval(context.Background(), request.src, metaSrc)
	if err != nil {
		return err
	}
	gologger.Verbose().Msgf("[%s] Executed code on local machine %v", request.options.TemplateID, input.MetaInput.Input)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Code Protocol request variables: \n%s\n", vardump.DumpVariables(variables))
	}

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("[%s] Dumped Executed Source Code for %v\n\n%v\n", request.options.TemplateID, input.MetaInput.Input, request.Source)
	}

	dataOutputString := fmtStdout(gOutput.Stdout.String())

	data := make(output.InternalEvent)

	data["type"] = request.Type().String()
	data["response"] = dataOutputString // response contains filtered output (eg without trailing \n)
	data["input"] = input.MetaInput.Input
	data["template-path"] = request.options.TemplatePath
	data["template-id"] = request.options.TemplateID
	data["template-info"] = request.options.TemplateInfo
	if gOutput.Stderr.Len() > 0 {
		data["stderr"] = fmtStdout(gOutput.Stderr.String())
	}

	// expose response variables in proto_var format
	// this is no-op if the template is not a multi protocol template
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, data)

	// add variables from template context before matching/extraction
	data = generators.MergeMaps(data, request.options.GetTemplateCtx(input.MetaInput).GetAll())

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
		msg := fmt.Sprintf("[%s] Dumped Code Execution for %s\n\n", request.options.TemplateID, input.MetaInput.Input)
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
	return templateTypes.CodeProtocol
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Matched:          types.ToString(wrapped.InternalEvent["input"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
	}
	return data
}

func fmtStdout(data string) string {
	return strings.Trim(data, " \n\r\t")
}
