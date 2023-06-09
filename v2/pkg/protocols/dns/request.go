package dns

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/retryabledns"
	iputil "github.com/projectdiscovery/utils/ip"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.DNSProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// Parse the URL and return domain if URL.
	var domain string
	if utils.IsURL(input.MetaInput.Input) {
		domain = extractDomain(input.MetaInput.Input)
	} else {
		domain = input.MetaInput.Input
	}

	var err error
	domain, err = request.parseDNSInput(domain)
	if err != nil {
		return errors.Wrap(err, "could not build request")
	}

	vars := protocolutils.GenerateDNSVariables(domain)
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	// merge with metadata (eg. from workflow context)
	vars = generators.MergeMaps(vars, metadata, optionVars)
	variablesMap := request.options.Variables.Evaluate(vars)
	vars = generators.MergeMaps(vars, variablesMap, request.options.Constants)

	if request.generator != nil {
		iterator := request.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			value = generators.MergeMaps(vars, value)
			if err := request.execute(domain, metadata, previous, value, callback); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(vars)
		return request.execute(domain, metadata, previous, value, callback)
	}
	return nil
}

func (request *Request) execute(domain string, metadata, previous output.InternalEvent, vars map[string]interface{}, callback protocols.OutputEventCallback) error {

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(vars))
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := request.Make(domain, vars)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not build request")
	}

	dnsClient := request.dnsClient
	if varErr := expressions.ContainsUnresolvedVariables(request.Resolvers...); varErr != nil {
		if dnsClient, varErr = request.getDnsClient(request.options, metadata); varErr != nil {
			gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, domain, varErr)
			return nil
		}
	}
	question := domain
	if len(compiledRequest.Question) > 0 {
		question = compiledRequest.Question[0].Name
	}
	// remove the last dot
	question = strings.TrimSuffix(question, ".")

	requestString := compiledRequest.String()
	if varErr := expressions.ContainsUnresolvedVariables(requestString); varErr != nil {
		gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, question, varErr)
		return nil
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped DNS request for %s", request.options.TemplateID, question)
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Str("domain", domain).Msgf(msg)
			gologger.Print().Msgf("%s", requestString)
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(domain, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, requestString))
		}
	}

	request.options.RateLimiter.Take()

	// Send the request to the target servers
	response, err := dnsClient.Do(compiledRequest)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
	} else {
		request.options.Progress.IncrementRequests()
	}
	if response == nil {
		return errors.Wrap(err, "could not send dns request")
	}

	request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
	gologger.Verbose().Msgf("[%s] Sent DNS request to %s\n", request.options.TemplateID, question)

	// perform trace if necessary
	var traceData *retryabledns.TraceData
	if request.Trace {
		traceData, err = request.dnsClient.Trace(domain, request.question, request.TraceMaxRecursion)
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, domain, "dns", err)
		}
	}

	// Create the output event
	outputEvent := request.responseToDSLMap(compiledRequest, response, domain, question, traceData)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range vars {
		outputEvent[k] = v
	}
	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

	dumpResponse(event, request, request.options, response.String(), question)
	if request.Trace {
		dumpTraceData(event, request.options, traceToString(traceData, true), question)
	}

	callback(event)
	return nil
}

func (request *Request) parseDNSInput(host string) (string, error) {
	isIP := iputil.IsIP(host)
	switch {
	case request.question == dns.TypePTR && isIP:
		var err error
		host, err = dns.ReverseAddr(host)
		if err != nil {
			return "", err
		}
	default:
		if isIP {
			return "", errors.New("cannot use IP address as DNS input")
		}
		host = dns.Fqdn(host)
	}
	return host, nil
}

func dumpResponse(event *output.InternalWrappedEvent, request *Request, requestOptions *protocols.ExecutorOptions, response, domain string) {
	cliOptions := request.options.Options
	if cliOptions.Debug || cliOptions.DebugResponse || cliOptions.StoreResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(response) {
			hexDump = true
			response = hex.Dump([]byte(response))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, response, cliOptions.NoColor, hexDump)
		msg := fmt.Sprintf("[%s] Dumped DNS response for %s\n\n%s", request.options.TemplateID, domain, highlightedResponse)
		if cliOptions.Debug || cliOptions.DebugResponse {
			gologger.Debug().Msg(msg)
		}
		if cliOptions.StoreResponse {
			request.options.Output.WriteStoreDebugData(domain, request.options.TemplateID, request.Type().String(), msg)
		}
	}
}

func dumpTraceData(event *output.InternalWrappedEvent, requestOptions *protocols.ExecutorOptions, traceData, domain string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(traceData) {
			hexDump = true
			traceData = hex.Dump([]byte(traceData))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, traceData, cliOptions.NoColor, hexDump)
		gologger.Debug().Msgf("[%s] Dumped DNS Trace data for %s\n\n%s", requestOptions.TemplateID, domain, highlightedResponse)
	}
}

// extractDomain extracts the domain name of a URL
func extractDomain(theURL string) string {
	u, err := url.Parse(theURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
