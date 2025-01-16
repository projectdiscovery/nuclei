package code

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/alecthomas/chroma/quick"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/dop251/goja"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
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
	contextutil "github.com/projectdiscovery/utils/context"
	"github.com/projectdiscovery/utils/errkit"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	pythonEnvRegex = `os\.getenv\(['"]([^'"]+)['"]\)`
)

var (
	// pythonEnvRegexCompiled is the compiled regex for python environment variables
	pythonEnvRegexCompiled = regexp.MustCompile(pythonEnvRegex)
	// ErrCodeExecutionDeadline is the error returned when alloted time for script execution exceeds
	ErrCodeExecutionDeadline = errkit.New("code execution deadline exceeded").SetKind(errkit.ErrKindDeadline).Build()
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID of the Request"`
	// description: |
	//   Engine type
	Engine []string `yaml:"engine,omitempty" json:"engine,omitempty" jsonschema:"title=engine,description=Engine"`
	// description: |
	//   PreCondition is a condition which is evaluated before sending the request.
	PreCondition string `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty" jsonschema:"title=pre-condition for the request,description=PreCondition is a condition which is evaluated before sending the request"`
	// description: |
	//   Engine Arguments
	Args []string `yaml:"args,omitempty" json:"args,omitempty" jsonschema:"title=args,description=Args"`
	// description: |
	//   Pattern preferred for file name
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty" jsonschema:"title=pattern,description=Pattern"`
	// description: |
	//   Source File/Snippet
	Source string `yaml:"source,omitempty" json:"source,omitempty" jsonschema:"title=source file/snippet,description=Source snippet"`

	options              *protocols.ExecutorOptions `yaml:"-" json:"-"`
	preConditionCompiled *goja.Program              `yaml:"-" json:"-"`
	gozero               *gozero.Gozero             `yaml:"-" json:"-"`
	src                  *gozero.Source             `yaml:"-" json:"-"`
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	gozeroOptions := &gozero.Options{
		Engines:                  request.Engine,
		Args:                     request.Args,
		EarlyCloseFileDescriptor: true,
	}

	if options.Options.Debug || options.Options.DebugResponse {
		// enable debug mode for gozero
		gozeroOptions.DebugMode = true
	}

	engine, err := gozero.New(gozeroOptions)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("[%s] engines '%s' not available on host", options.TemplateID, strings.Join(request.Engine, ","))
	}
	request.gozero = engine

	var src *gozero.Source

	src, err = gozero.NewSourceWithString(request.Source, request.Pattern, request.options.TemporaryDirectory)
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

	// compile pre-condition if any
	if request.PreCondition != "" {
		preConditionCompiled, err := compiler.WrapScriptNCompile(request.PreCondition, false)
		if err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not compile pre-condition: %s", err)
		}
		request.preConditionCompiled = preConditionCompiled
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
	metaSrc, err := gozero.NewSourceWithString(input.MetaInput.Input, "", request.options.TemporaryDirectory)
	if err != nil {
		return err
	}
	defer func() {
		if err := metaSrc.Cleanup(); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}()

	var interactshURLs []string

	// inject all template context values as gozero env allvars
	allvars := protocolutils.GenerateVariables(input.MetaInput.Input, false, nil)
	// add template context values if available
	if request.options.HasTemplateCtx(input.MetaInput) {
		allvars = generators.MergeMaps(allvars, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	// add dynamic and previous variables
	allvars = generators.MergeMaps(allvars, dynamicValues, previous)
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	variablesMap := request.options.Variables.Evaluate(allvars)
	// since we evaluate variables using allvars, give precedence to variablesMap
	allvars = generators.MergeMaps(allvars, variablesMap, optionVars, request.options.Constants)
	for name, value := range allvars {
		v := fmt.Sprint(value)
		v, interactshURLs = request.options.Interactsh.Replace(v, interactshURLs)
		// if value is updated by interactsh, update allvars to reflect the change downstream
		allvars[name] = v
		metaSrc.AddVariable(gozerotypes.Variable{Name: name, Value: v})
	}

	if request.PreCondition != "" {
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Debug().Msgf("[%s] Executing Precondition for Code request\n", request.TemplateID)
			var highlightFormatter = "terminal256"
			if request.options.Options.NoColor {
				highlightFormatter = "text"
			}
			var buff bytes.Buffer
			_ = quick.Highlight(&buff, beautifyJavascript(request.PreCondition), "javascript", highlightFormatter, "monokai")
			prettyPrint(request.TemplateID, buff.String())
		}

		args := compiler.NewExecuteArgs()
		args.TemplateCtx = allvars

		result, err := request.options.JsCompiler.ExecuteWithOptions(request.preConditionCompiled, args,
			&compiler.ExecuteOptions{
				TimeoutVariants: request.options.Options.GetTimeouts(),
				Source:          &request.PreCondition,
				Callback:        registerPreConditionFunctions,
				Cleanup:         cleanUpPreConditionFunctions,
				Context:         input.Context(),
			})
		if err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not execute pre-condition: %s", err)
		}
		if !result.GetSuccess() || types.ToString(result["error"]) != "" {
			gologger.Warning().Msgf("[%s] Precondition for request %s was not satisfied\n", request.TemplateID, request.PreCondition)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return nil
		}
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Debug().Msgf("[%s] Precondition for request was satisfied\n", request.TemplateID)
		}
	}

	ctx, cancel := context.WithTimeoutCause(input.Context(), request.options.Options.GetTimeouts().CodeExecutionTimeout, ErrCodeExecutionDeadline)
	defer cancel()
	// Note: we use contextutil despite the fact that gozero accepts context as argument
	gOutput, err := contextutil.ExecFuncWithTwoReturns(ctx, func() (*gozerotypes.Result, error) {
		return request.gozero.Eval(ctx, request.src, metaSrc)
	})
	if gOutput == nil {
		// write error to stderr buff
		var buff bytes.Buffer
		if err != nil {
			buff.WriteString(err.Error())
		} else {
			buff.WriteString("no output something went wrong")
		}
		gOutput = &gozerotypes.Result{
			Stderr: buff,
		}
	}
	gologger.Verbose().Msgf("[%s] Executed code on local machine %v", request.options.TemplateID, input.MetaInput.Input)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Code Protocol request variables: %s\n", vardump.DumpVariables(allvars))
	}

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().MsgFunc(func() string {
			dashes := strings.Repeat("-", 15)
			sb := &strings.Builder{}
			sb.WriteString(fmt.Sprintf("[%s] Dumped Executed Source Code for input/stdin: '%v'", request.options.TemplateID, input.MetaInput.Input))
			sb.WriteString(fmt.Sprintf("\n%v\n%v\n%v\n", dashes, "Source Code:", dashes))
			sb.WriteString(interpretEnvVars(request.Source, allvars))
			sb.WriteString("\n")
			sb.WriteString(fmt.Sprintf("\n%v\n%v\n%v\n", dashes, "Command Executed:", dashes))
			sb.WriteString(interpretEnvVars(gOutput.Command, allvars))
			sb.WriteString("\n")
			sb.WriteString(fmt.Sprintf("\n%v\n%v\n%v\n", dashes, "Command Output:", dashes))
			sb.WriteString(gOutput.DebugData.String())
			sb.WriteString("\n")
			sb.WriteString("[WRN] Command Output here is stdout+sterr, in response variables they are seperate (use -v -svd flags for more details)")
			return sb.String()
		})
	}

	dataOutputString := fmtStdout(gOutput.Stdout.String())

	data := make(output.InternalEvent)
	// also include all request variables in result event
	for _, value := range metaSrc.Variables {
		data[value.Name] = value.Value
	}

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
	fields := protocolutils.GetJsonFieldsFromURL(types.ToString(wrapped.InternalEvent["input"]))
	if types.ToString(wrapped.InternalEvent["ip"]) != "" {
		fields.Ip = types.ToString(wrapped.InternalEvent["ip"])
	}
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		TemplateVerifier: request.options.TemplateVerifier,
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

func fmtStdout(data string) string {
	return strings.Trim(data, " \n\r\t")
}

// interpretEnvVars replaces environment variables in the input string
func interpretEnvVars(source string, vars map[string]interface{}) string {
	// bash mode
	if strings.Contains(source, "$") {
		for k, v := range vars {
			source = strings.ReplaceAll(source, "$"+k, fmt.Sprintf("%s", v))
		}
	}
	// python mode
	if strings.Contains(source, "os.getenv") {
		matches := pythonEnvRegexCompiled.FindAllStringSubmatch(source, -1)
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			source = strings.ReplaceAll(source, fmt.Sprintf("os.getenv('%s')", match), fmt.Sprintf("'%s'", vars[match[0]]))
		}
	}
	return source
}

func beautifyJavascript(code string) string {
	opts := jsbeautifier.DefaultOptions()
	beautified, err := jsbeautifier.Beautify(&code, opts)
	if err != nil {
		return code
	}
	return beautified
}

func prettyPrint(templateId string, buff string) {
	lines := strings.Split(buff, "\n")
	final := []string{}
	for _, v := range lines {
		if v != "" {
			final = append(final, "\t"+v)
		}
	}
	gologger.Debug().Msgf(" [%v] Pre-condition Code:\n\n%v\n\n", templateId, strings.Join(final, "\n"))
}
