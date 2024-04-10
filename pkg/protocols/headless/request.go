package headless

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

var _ protocols.Request = &Request{}

const errCouldGetHtmlElement = "could get html element"

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent) <-chan protocols.Result {
	results := make(chan protocols.Result)
	onResult := func(events ...*output.InternalWrappedEvent) {
		for _, event := range events {
			results <- protocols.Result{Event: event}
		}
	}

	var errGroup errgroup.Group

	errGroup.Go(func() error {
		if request.SelfContained {
			url, err := extractBaseURLFromActions(request.Steps)
			if err != nil {
				return err
			}
			input = contextargs.NewWithInput(url)
		}

		if request.options.Browser.UserAgent() == "" {
			request.options.Browser.SetUserAgent(request.compiledUserAgent)
		}

		vars := protocolutils.GenerateVariablesWithContextArgs(input, false)
		payloads := generators.BuildPayloadFromOptions(request.options.Options)
		// add templatecontext variables to varMap
		values := generators.MergeMaps(vars, metadata, payloads)
		if request.options.HasTemplateCtx(input.MetaInput) {
			values = generators.MergeMaps(values, request.options.GetTemplateCtx(input.MetaInput).GetAll())
		}
		variablesMap := request.options.Variables.Evaluate(values)
		payloads = generators.MergeMaps(variablesMap, payloads, request.options.Constants)

		// check for operator matches by wrapping callback
		gotmatches := false
		// verify if fuzz elaboration was requested
		if len(request.Fuzzing) > 0 {
			events, err := request.executeFuzzingRule(input, payloads)
			onResult(events...)
			return err
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
				event, err := request.executeRequestWithPayloads(input, value)
				results <- protocols.Result{Event: event}
				if event != nil && event.OperatorsResult != nil {
					gotmatches = event.OperatorsResult.Matched
				}
				if err != nil {
					return err
				}
			}
		} else {
			value := maps.Clone(payloads)
			event, err := request.executeRequestWithPayloads(input, value)
			onResult(event)
			if err != nil {
				return err
			}
		}
		return nil
	})

	go func() {
		defer close(results)
		if err := errGroup.Wait(); err != nil {
			results <- protocols.Result{Error: err}
		}
	}()

	return results
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

func (request *Request) executeRequestWithPayloads(input *contextargs.Context, payloads map[string]interface{}) (*output.InternalWrappedEvent, error) {
	instance, err := request.options.Browser.NewInstance()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return nil, errors.Wrap(err, errCouldGetHtmlElement)
	}
	defer instance.Close()

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Headless Protocol request variables: \n%s\n", vardump.DumpVariables(payloads))
	}

	instance.SetInteractsh(request.options.Interactsh)

	if _, err := url.Parse(input.MetaInput.Input); err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return nil, errors.Wrap(err, errCouldGetHtmlElement)
	}
	options := &engine.Options{
		Timeout:       time.Duration(request.options.Options.PageTimeout) * time.Second,
		DisableCookie: request.DisableCookie,
		Options:       request.options.Options,
	}

	if !options.DisableCookie && input.CookieJar == nil {
		return nil, errors.New("cookie reuse enabled but cookie-jar is nil")
	}

	out, page, err := instance.Run(input, request.Steps, payloads, options)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return nil, errors.Wrap(err, errCouldGetHtmlElement)
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

	switch {
	case len(page.InteractshURLs) == 0:
		event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
		event.UsesInteractsh = len(page.InteractshURLs) > 0
		dumpResponse(event, request.options, responseBody, input.MetaInput.Input)
		return event, nil
	case request.options.Interactsh != nil:
		event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
		event.UsesInteractsh = len(page.InteractshURLs) > 0
		request.options.Interactsh.RequestEvent(page.InteractshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
		dumpResponse(event, request.options, responseBody, input.MetaInput.Input)
	default:
		dumpResponse(nil, request.options, responseBody, input.MetaInput.Input)
		return nil, nil
	}
	return nil, nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecutorOptions, responseBody string, input string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, responseBody, cliOptions.NoColor, false)
		gologger.Debug().Msgf("[%s] Dumped Headless response for %s\n\n%s", requestOptions.TemplateID, input, highlightedResponse)
	}
}

// executeFuzzingRule executes a fuzzing rule in the template request
func (request *Request) executeFuzzingRule(input *contextargs.Context, payloads map[string]interface{}) ([]*output.InternalWrappedEvent, error) {
	gotmatches := false
	var events []*output.InternalWrappedEvent

	fuzzRequestCallback := func(gr fuzz.GeneratedRequest) bool {
		if gotmatches && (request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch) {
			return true
		}
		newInput := input.Clone()
		newInput.MetaInput.Input = gr.Request.URL.String()
		event, err := request.executeRequestWithPayloads(newInput, gr.DynamicValues)
		events = append(events, event)
		return err == nil
	}

	if _, err := urlutil.Parse(input.MetaInput.Input); err != nil {
		return events, errors.Wrap(err, "could not parse url")
	}
	baseRequest, err := retryablehttp.NewRequest("GET", input.MetaInput.Input, nil)
	if err != nil {
		return events, errors.Wrap(err, "could not create base request")
	}
	for _, rule := range request.Fuzzing {
		err := rule.Execute(&fuzz.ExecuteRuleInput{
			Input:       input,
			Callback:    fuzzRequestCallback,
			Values:      payloads,
			BaseRequest: baseRequest,
		})
		if err == types.ErrNoMoreRequests {
			return events, nil
		}
		if err != nil {
			return events, errors.Wrap(err, "could not execute rule")
		}
	}
	return events, nil
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
