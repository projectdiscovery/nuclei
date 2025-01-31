package headless

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

var _ protocols.Request = &Request{}

const errCouldNotGetHtmlElement = "could not get html element"

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if request.SelfContained {
		url, err := extractBaseURLFromActions(request.Steps)
		if err != nil {
			return err
		}
		input = contextargs.NewWithInput(input.Context(), url)
	}

	if request.options.Browser.UserAgent() == "" {
		request.options.Browser.SetUserAgent(request.compiledUserAgent)
	}

	vars := protocolutils.GenerateVariablesWithContextArgs(input, false)
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	// add templatecontext variables to varMap
	if request.options.HasTemplateCtx(input.MetaInput) {
		vars = generators.MergeMaps(vars, metadata, optionVars, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	variablesMap := request.options.Variables.Evaluate(vars)
	vars = generators.MergeMaps(vars, variablesMap, request.options.Constants)

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
		return request.executeFuzzingRule(input, vars, previous, wrappedCallback)
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
			value = generators.MergeMaps(value, vars)
			if err := request.executeRequestWithPayloads(input, value, previous, wrappedCallback); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(vars)
		if err := request.executeRequestWithPayloads(input, value, previous, wrappedCallback); err != nil {
			return err
		}
	}
	return nil
}

// This function extracts the base URL from actions.
func extractBaseURLFromActions(steps []*engine.Action) (string, error) {
	for _, action := range steps {
		if action.ActionType.ActionType == engine.ActionNavigate {
			navigateURL := action.GetArg("url")
			url, err := urlutil.Parse(navigateURL)
			if err != nil {
				return "", errors.Errorf("could not parse URL '%s': %s", navigateURL, err.Error())
			}
			return fmt.Sprintf("%s://%s", url.Scheme, url.Host), nil
		}
	}
	return "", errors.New("no navigation action found")
}

func (request *Request) executeRequestWithPayloads(input *contextargs.Context, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	instance, err := request.options.Browser.NewInstance()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
	}
	defer instance.Close()

	instance.SetInteractsh(request.options.Interactsh)

	if _, err := url.Parse(input.MetaInput.Input); err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
	}
	options := &engine.Options{
		Timeout:       time.Duration(request.options.Options.PageTimeout) * time.Second,
		DisableCookie: request.DisableCookie,
		Options:       request.options.Options,
	}

	if !options.DisableCookie && input.CookieJar == nil {
		return errors.New("cookie reuse enabled but cookie-jar is nil")
	}

	out, page, err := instance.Run(input, request.Steps, payloads, options)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
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
		gologger.Debug().Msg(reqBuilder.String())
	}

	var responseBody string
	html, err := page.Page().Element("html")
	if err == nil {
		responseBody, _ = html.HTML()
	}

	header := out.GetOrDefault("header", "").(string)

	// NOTE(dwisiswant0): `status_code` key should be an integer type.
	// Ref: https://github.com/projectdiscovery/nuclei/pull/5545#discussion_r1721291013
	statusCode := out.GetOrDefault("status_code", "").(string)

	outputEvent := request.responseToDSLMap(responseBody, header, statusCode, reqBuilder.String(), input.MetaInput.Input, navigatedURL, page.DumpHistory())
	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
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
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	if shouldStopAtFirstMatch && event.HasOperatorResult() {
		return types.ErrNoMoreRequests
	}
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
	baseRequest, err := retryablehttp.NewRequest("GET", input.MetaInput.Input, nil)
	if err != nil {
		return errors.Wrap(err, "could not create base request")
	}
	for _, rule := range request.Fuzzing {
		err := rule.Execute(&fuzz.ExecuteRuleInput{
			Input:       input,
			Callback:    fuzzRequestCallback,
			Values:      payloads,
			BaseRequest: baseRequest,
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
