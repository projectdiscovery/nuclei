package headless

import (
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(inputURL string, metadata, previous output.InternalEvent /*TODO review unused parameter*/, callback protocols.OutputEventCallback) error {
	payloads := generators.BuildPayloadFromOptions(request.options.Options)
	if request.generator != nil {
		iterator := request.generator.NewIterator()
		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			value = generators.MergeMaps(value, payloads)
			if err := request.executeRequestWithPayloads(inputURL, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := generators.CopyMap(payloads)
		if err := request.executeRequestWithPayloads(inputURL, value, previous, callback); err != nil {
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
		return errors.Wrap(err, "could get html element")
	}
	defer instance.Close()

	instance.SetInteractsh(request.options.Interactsh)

	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	timeout := time.Duration(request.options.Options.PageTimeout) * time.Second
	out, page, err := instance.Run(parsedURL, request.Steps, payloads, timeout)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	defer page.Close()

	request.options.Output.Request(request.options.TemplatePath, inputURL, request.Type().String(), nil)
	request.options.Progress.IncrementRequests()
	gologger.Verbose().Msgf("Sent Headless request to %s", inputURL)

	reqBuilder := &strings.Builder{}
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped Headless request for %s", request.options.TemplateID, inputURL)

		for _, act := range request.Steps {
			reqBuilder.WriteString(act.String())
			reqBuilder.WriteString("\n")
		}
		gologger.Print().Msgf(reqBuilder.String())
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
