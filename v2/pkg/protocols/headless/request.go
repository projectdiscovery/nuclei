package headless

import (
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

const errCouldGetHtmlElement = "could get html element"

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	inputURL := input.MetaInput.Input
	if request.options.Browser.UserAgent() == "" {
		request.options.Browser.SetUserAgent(request.compiledUserAgent)
	}

	vars := protocolutils.GenerateVariablesWithContextArgs(input, false)
	payloads := generators.BuildPayloadFromOptions(request.options.Options)
	values := generators.MergeMaps(vars, metadata, payloads)
	variablesMap := request.options.Variables.Evaluate(values)
	payloads = generators.MergeMaps(variablesMap, payloads)

	// check for operator matches by wrapping callback
	gotmatches := false
	wrappedCallback := func(results *output.InternalWrappedEvent) {
		callback(results)
		if results != nil && results.OperatorsResult != nil {
			gotmatches = results.OperatorsResult.Matched
		}
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
			if err := request.executeRequestWithPayloads(inputURL, value, previous, wrappedCallback); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(payloads)
		if err := request.executeRequestWithPayloads(inputURL, value, previous, wrappedCallback); err != nil {
			return err
		}
	}
	return nil
}

func (request *Request) executeRequestWithPayloads(inputURL string, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	instance, err := request.options.Browser.NewInstance()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	defer instance.Close()

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(payloads))
	}

	instance.SetInteractsh(request.options.Interactsh)

	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	timeout := time.Duration(request.options.Options.PageTimeout) * time.Second
	out, page, err := instance.Run(parsedURL, request.Steps, payloads, timeout)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldGetHtmlElement)
	}
	defer page.Close()

	request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), nil)
	request.options.Progress.IncrementRequests()
	gologger.Verbose().Msgf("Sent Headless request to %s", inputURL)

	reqBuilder := &strings.Builder{}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.DebugResponse {
		gologger.Info().Msgf("[%s] Dumped Headless request for %s", request.options.TemplateID, inputURL)

		for _, act := range request.Steps {
			actStepStr := act.String()
			actStepStr = strings.ReplaceAll(actStepStr, "{{BaseURL}}", inputURL)
			reqBuilder.WriteString("\t" + actStepStr + "\n")
		}
		gologger.Debug().Msgf(reqBuilder.String())

	}

	var responseBody string
	html, err := page.Page().Element("html")
	if err == nil {
		responseBody, _ = html.HTML()
	}

	outputEvent := request.responseToDSLMap(responseBody, reqBuilder.String(), inputURL, inputURL, page.DumpHistory())
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

	dumpResponse(event, request.options, responseBody, inputURL)
	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, responseBody string, input string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, responseBody, cliOptions.NoColor, false)
		gologger.Debug().Msgf("[%s] Dumped Headless response for %s\n\n%s", requestOptions.TemplateID, input, highlightedResponse)
	}
}
