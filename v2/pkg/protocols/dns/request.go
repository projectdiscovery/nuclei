package dns

import (
	"net/url"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// Parse the URL and return domain if URL.
	var domain string
	if isURL(input) {
		domain = extractDomain(input)
	} else {
		domain = input
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := r.Make(domain)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, domain, "dns", err)
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not build request")
	}

	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Str("domain", domain).Msgf("[%s] Dumped DNS request for %s", r.options.TemplateID, domain)
		gologger.Print().Msgf("%s", compiledRequest.String())
	}

	// Send the request to the target servers
	resp, err := r.dnsClient.Do(compiledRequest)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, domain, "dns", err)
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not send dns request")
	}
	r.options.Progress.IncrementRequests()

	r.options.Output.Request(r.options.TemplateID, domain, "dns", err)
	gologger.Verbose().Msgf("[%s] Sent DNS request to %s", r.options.TemplateID, domain)

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped DNS response for %s", r.options.TemplateID, domain)
		gologger.Print().Msgf("%s", resp.String())
	}
	outputEvent := r.responseToDSLMap(compiledRequest, resp, input, input)
	for k, v := range previous {
		outputEvent[k] = v
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)
	return nil
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
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
