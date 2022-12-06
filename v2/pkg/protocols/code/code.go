package code

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// description: |
	//   Engine type
	Engine EngineTypeHolder `yaml:"engine,omitempty" jsonschema:"title=engine,description=Engine,enum=python,enum=powershell,enum=command"`
	// description: |
	//   Source Snippet
	Source  string `yaml:"source,omitempty" jsonschema:"title=source snippet,description=Source snippet"`
	options *protocols.ExecuterOptions
	gozero  *gozero.Gozero
	cmd     *gozero.Command
	src     *gozero.Source
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	request.options = options

	gozeroOptions := &gozero.Options{
		Engine: request.Engine.EngineType.Executable(),
	}
	engine, err := gozero.New(gozeroOptions)
	if err != nil {
		return err
	}
	request.gozero = engine

	switch request.Engine.EngineType {
	case Command:
		cmdTokens := strings.Split(request.Source, " ")
		cmd, err := gozero.NewCommandWithString(cmdTokens[0], cmdTokens[1:]...)
		if err != nil {
			return err
		}
		request.cmd = cmd
	default:
		src, err := gozero.NewSourceWithString(request.Source)
		if err != nil {
			return err
		}
		request.src = src
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
	metaSrc, err := gozero.NewSourceWithString(input.MetaInput.Input)
	if err != nil {
		return err
	}
	defer metaSrc.Cleanup() //nolint

	var output *gozero.Source
	switch request.Engine.EngineType {
	case Command:
		output, err = request.gozero.Exec(context.Background(), metaSrc, request.cmd)
	default:
		output, err = request.gozero.Eval(context.Background(), request.src, metaSrc)
	}

	if err != nil {
		return err
	}
	defer output.Cleanup() //nolint

	dataOutput, err := output.ReadAll()
	if err != nil {
		return err
	}
	dataOutputString := string(dataOutput)

	data := make(map[string]interface{})

	data["type"] = request.Type().String()
	data["response"] = string(dataOutput)
	data["body"] = string(dataOutput)
	data["input"] = input.MetaInput.Input
	data["template-path"] = request.options.TemplatePath
	data["template-id"] = request.options.TemplateID
	data["template-info"] = request.options.TemplateInfo

	event := eventcreator.CreateEvent(request, data, request.options.Options.Debug || request.options.Options.DebugResponse)
	if request.options.Options.Debug || request.options.Options.DebugResponse || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Code Execution for %s", request.options.TemplateID, input.MetaInput.Input)
		if request.options.Options.Debug || request.options.Options.DebugResponse {
			gologger.Debug().Msg(msg)
			gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, dataOutputString, request.options.Options.NoColor, false))
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
