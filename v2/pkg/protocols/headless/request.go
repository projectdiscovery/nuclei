package headless

import (
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(inputURL string, metadata, previous output.InternalEvent /*TODO review unused parameter*/, callback protocols.OutputEventCallback) error {
	instance, err := request.options.Browser.NewInstance()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, "headless", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	defer instance.Close()

	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, "headless", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	out, page, err := instance.Run(parsedURL, request.Steps, time.Duration(request.options.Options.PageTimeout)*time.Second)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, inputURL, "headless", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	defer page.Close()

	request.options.Output.Request(request.options.TemplatePath, inputURL, "headless", nil)
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
	outputEvent := request.responseToDSLMap(responseBody, reqBuilder.String(), inputURL, inputURL)
	for k, v := range out {
		outputEvent[k] = v
	}

	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

	debug(event, request, responseBody, inputURL)

	callback(event)
	return nil
}

func debug(event *output.InternalWrappedEvent, request *Request, responseBody string, input string) {
	if request.options.Options.Debug || request.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped Headless response for %s\n", request.options.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, responseBody, request.options.Options.NoColor, false))
	}
}
