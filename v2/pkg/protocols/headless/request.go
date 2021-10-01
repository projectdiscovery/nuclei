package headless

import (
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent /*TODO review unused parameter*/, callback protocols.OutputEventCallback) error {
	instance, err := r.options.Browser.NewInstance()
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "headless", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	defer instance.Close()

	parsed, err := url.Parse(input)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "headless", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	out, page, err := instance.Run(parsed, r.Steps, time.Duration(r.options.Options.PageTimeout)*time.Second)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "headless", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could get html element")
	}
	defer page.Close()

	r.options.Output.Request(r.options.TemplateID, input, "headless", nil)
	r.options.Progress.IncrementRequests()
	gologger.Verbose().Msgf("Sent Headless request to %s", input)

	reqBuilder := &strings.Builder{}
	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped Headless request for %s", r.options.TemplateID, input)

		for _, act := range r.Steps {
			reqBuilder.WriteString(act.String())
			reqBuilder.WriteString("\n")
		}
		gologger.Print().Msgf("%s", reqBuilder.String())
	}

	var responseBody string
	html, err := page.Page().Element("html")
	if err == nil {
		responseBody, _ = html.HTML()
	}
	outputEvent := r.responseToDSLMap(responseBody, reqBuilder.String(), input, input)
	for k, v := range out {
		outputEvent[k] = v
	}

	event := createEvent(r, outputEvent)

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped Headless response for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, responseBody, r.options.Options.NoColor))
	}

	callback(event)
	return nil
}

func createEvent(request *Request, outputEvent output.InternalEvent) *output.InternalWrappedEvent {
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}

	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(outputEvent, request.Match, request.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = request.MakeResultEvent(event)
		}
	}

	return event
}
