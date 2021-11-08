package dns

import (
	"encoding/hex"
	"net/url"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// Parse the URL and return domain if URL.
	var domain string
	if isURL(input) {
		domain = extractDomain(input)
	} else {
		domain = input
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := request.Make(domain)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, "dns", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not build request")
	}

	requestString := compiledRequest.String()
	if varErr := expressions.ContainsUnresolvedVariables(requestString); varErr != nil {
		gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, domain, varErr)
		return nil
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Info().Str("domain", domain).Msgf("[%s] Dumped DNS request for %s", request.options.TemplateID, domain)
		gologger.Print().Msgf("%s", requestString)
	}

	// Send the request to the target servers
	response, err := request.dnsClient.Do(compiledRequest)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, "dns", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
	}
	if response == nil {
		return errors.Wrap(err, "could not send dns request")
	}
	request.options.Progress.IncrementRequests()

	request.options.Output.Request(request.options.TemplatePath, domain, "dns", err)
	gologger.Verbose().Msgf("[%s] Sent DNS request to %s\n", request.options.TemplateID, domain)

	outputEvent := request.responseToDSLMap(compiledRequest, response, input, input)
	for k, v := range previous {
		outputEvent[k] = v
	}

	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

	dumpResponse(event, request.options, response.String(), domain)

	callback(event)
	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, response string, domain string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(response) {
			hexDump = true
			response = hex.Dump([]byte(response))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, response, cliOptions.NoColor, hexDump)
		gologger.Debug().Msgf("[%s] Dumped DNS response for %s\n\n%s", requestOptions.TemplateID, domain, highlightedResponse)
	}
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	if _, err := url.ParseRequestURI(toTest); err != nil {
		return false
	}
	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

// extractDomain extracts the domain name of a URL
func extractDomain(theURL string) string {
	u, err := url.Parse(theURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
