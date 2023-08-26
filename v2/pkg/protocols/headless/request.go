package headless

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

var _ protocols.Request = &Request{}

const errCouldGetHtmlElement = "could get html element"

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if request.options.Browser.UserAgent() == "" {
		request.options.Browser.SetUserAgent(request.compiledUserAgent)
	}

	vars := protocolutils.GenerateVariablesWithContextArgs(input, false)
	payloads := generators.BuildPayloadFromOptions(request.options.Options)
	values := generators.MergeMaps(vars, metadata, payloads)
	variablesMap := request.options.Variables.Evaluate(values)
	payloads = generators.MergeMaps(variablesMap, payloads, request.options.Constants)

	// check for operator matches by wrapping callback
	gotmatches := false
	wrappedCallback := func(results *output.InternalWrappedEvent) {
		callback(results)
		if results != nil && results.OperatorsResult != nil {
			gotmatches = results.OperatorsResult.Matched
		}
	}
	// verify if fuzz elaboration was requested
	if len(request.Fuzzing) > 0 {
		return request.executeFuzzingRule(input, payloads, previous, wrappedCallback)
	}
	if request.generator != nil {
		iterator := request.generator.NewIterator()
		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			if gotmatches && (request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch) {
				return nil
			}
			value = generators.MergeMaps(value, payloads)
			if err := request.executeRequestWithPayloads(input, value, previous, wrappedCallback); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(payloads)
		if err := request.executeRequestWithPayloads(input, value, previous, wrappedCallback); err != nil {
			return err
		}
	}
	return nil
}

func (request *Request) executeRequestWithPayloads(input *contextargs.Context, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	instance, err := request.options.Browser.NewInstance()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	defer instance.Close()

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(payloads))
	}

	instance.SetInteractsh(request.options.Interactsh)

	if _, err := url.Parse(input.MetaInput.Input); err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	options := &engine.Options{
		Timeout:     time.Duration(request.options.Options.PageTimeout) * time.Second,
		CookieReuse: request.CookieReuse,
		Options:     request.options.Options,
	}

	if options.CookieReuse && input.CookieJar == nil {
		return errors.New("cookie-reuse set but cookie-jar is nil")
	}

	out, page, err := instance.Run(input, request.Steps, payloads, options)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	defer page.Close()

	reqLog := instance.GetRequestLog()
	navigatedURL := request.getLastNavigationURLWithLog(reqLog) // also known as matchedURL if there is a match

	request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), nil)
	request.options.Progress.IncrementRequests()
	gologger.Verbose().Msgf("Sent Headless request to %s", navigatedURL)

	reqBuilder := &strings.Builder{}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.DebugResponse {
		gologger.Info().Msgf("[%s] Dumped Headless request for %s", request.options.TemplateID, navigatedURL)

		for _, act := range request.Steps {
			if act.ActionType.ActionType == engine.ActionNavigate {
				value := act.GetArg("url")
				if reqLog[value] != "" {
					reqBuilder.WriteString(fmt.Sprintf("\tnavigate => %v\n", reqLog[value]))
				} else {
					reqBuilder.WriteString(fmt.Sprintf("%v not found in %v\n", value, reqLog))
				}
			} else {
				actStepStr := act.String()
				reqBuilder.WriteString("\t" + actStepStr + "\n")
			}
		}
		gologger.Debug().Msgf(reqBuilder.String())
	}

	var responseBody string
	html, err := page.Page().Element("html")
	if err == nil {
		responseBody, _ = html.HTML()
	}

	outputEvent := request.responseToDSLMap(responseBody, out["header"], out["status_code"], reqBuilder.String(), input.MetaInput.Input, navigatedURL, page.DumpHistory())
	for k, v := range out {
		outputEvent[k] = v
	}
	for k, v := range payloads {
		outputEvent[k] = v
	}

	var event *output.InternalWrappedEvent
	if len(page.InteractshURLs) == 0 {
		event = eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: outputEvent}
		request.options.Interactsh.RequestEvent(page.InteractshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}
	if len(page.InteractshURLs) > 0 {
		event.UsesInteractsh = true
	}

	dumpResponse(event, request.options, responseBody, input.MetaInput.Input)
	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecutorOptions, responseBody string, input string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, responseBody, cliOptions.NoColor, false)
		gologger.Debug().Msgf("[%s] Dumped Headless response for %s\n\n%s", requestOptions.TemplateID, input, highlightedResponse)
	}
}

// executeFuzzingRule executes a fuzzing rule in the template request
func (request *Request) executeFuzzingRule(input *contextargs.Context, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// check for operator matches by wrapping callback
	gotmatches := false
	fuzzRequestCallback := func(gr fuzz.GeneratedRequest) bool {
		if gotmatches && (request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch) {
			return true
		}
		newInput := input.Clone()
		newInput.MetaInput.Input = gr.Request.URL.String()
		if err := request.executeRequestWithPayloads(newInput, gr.DynamicValues, previous, callback); err != nil {
			return false
		}
		return true
	}

	if _, err := urlutil.Parse(input.MetaInput.Input); err != nil {
		return errors.Wrap(err, "could not parse url")
	}
	for _, rule := range request.Fuzzing {
		err := rule.Execute(&fuzz.ExecuteRuleInput{
			Input:       input,
			Callback:    fuzzRequestCallback,
			Values:      payloads,
			BaseRequest: nil,
		})
		if err == types.ErrNoMoreRequests {
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "could not execute rule")
		}
	}
	return nil
}

// getLastNavigationURL returns last successfully navigated URL
func (request *Request) getLastNavigationURLWithLog(reqLog map[string]string) string {
	for i := len(request.Steps) - 1; i >= 0; i-- {
		if request.Steps[i].ActionType.ActionType == engine.ActionNavigate {
			templateURL := request.Steps[i].GetArg("url")
			if reqLog[templateURL] != "" {
				return reqLog[templateURL]
			}
		}
	}
	return ""
}
