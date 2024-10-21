package dns

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/retryabledns"
	iputil "github.com/projectdiscovery/utils/ip"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.DNSProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var err error
	domain, err := request.parseDNSInput(input.MetaInput.Input)
	if err != nil {
		return errors.Wrap(err, "could not build request")
	}

	vars := protocolutils.GenerateDNSVariables(domain)
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	// merge with metadata (eg. from workflow context)
	if request.options.HasTemplateCtx(input.MetaInput) {
		vars = generators.MergeMaps(vars, metadata, optionVars, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	variablesMap := request.options.Variables.Evaluate(vars)
	vars = generators.MergeMaps(vars, variablesMap, request.options.Constants)

	// if request threads matches global payload concurrency we follow it
	shouldFollowGlobal := request.Threads == request.options.Options.PayloadConcurrency

	if request.generator != nil {
		iterator := request.generator.NewIterator()
		swg, err := syncutil.New(syncutil.WithSize(request.Threads))
		if err != nil {
			return err
		}
		var multiErr error
		m := &sync.Mutex{}

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}

			select {
			case <-input.Context().Done():
				return input.Context().Err()
			default:
			}

			// resize check point - nop if there are no changes
			if shouldFollowGlobal && swg.Size != request.options.Options.PayloadConcurrency {
				if err := swg.Resize(input.Context(), request.options.Options.PayloadConcurrency); err != nil {
					return err
				}
			}

			value = generators.MergeMaps(vars, value)
			swg.Add()
			go func(newVars map[string]interface{}) {
				defer swg.Done()
				if err := request.execute(input, domain, metadata, previous, newVars, callback); err != nil {
					m.Lock()
					multiErr = multierr.Append(multiErr, err)
					m.Unlock()
				}
			}(value)
		}
		swg.Wait()
		if multiErr != nil {
			return multiErr
		}
	} else {
		value := maps.Clone(vars)
		return request.execute(input, domain, metadata, previous, value, callback)
	}
	return nil
}

func (request *Request) execute(input *contextargs.Context, domain string, metadata, previous output.InternalEvent, vars map[string]interface{}, callback protocols.OutputEventCallback) error {
	var err error
	if vardump.EnableVarDump {
		gologger.Debug().Msgf("DNS Protocol request variables: %s\n", vardump.DumpVariables(vars))
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
	domain = strings.TrimSuffix(domain, ".")
	question = strings.TrimSuffix(question, ".")

	requestString := compiledRequest.String()
	if varErr := expressions.ContainsUnresolvedVariables(requestString); varErr != nil {
		gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, question, varErr)
		return nil
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped DNS request for %s", request.options.TemplateID, question)
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Str("domain", domain).Msg(msg)
			gologger.Print().Msgf("%s", requestString)
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(domain, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, requestString))
		}
	}

	request.options.RateLimitTake()

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
	// expose response variables in proto_var format
	// this is no-op if the template is not a multi protocol template
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range vars {
		outputEvent[k] = v
	}
	// add variables from template context before matching/extraction
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

	dumpResponse(event, request, request.options, response.String(), question)
	if request.Trace {
		dumpTraceData(event, request.options, traceToString(traceData, true), question)
	}

	callback(event)
	return err
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

func dumpResponse(event *output.InternalWrappedEvent, request *Request, _ *protocols.ExecutorOptions, response, domain string) {
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
