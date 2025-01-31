package network

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/projectdiscovery/utils/reader"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.NetworkProtocol
}

// getOpenPorts returns all open ports from list of ports provided in template
// if only 1 port is provided, no need to check if port is open or not
func (request *Request) getOpenPorts(target *contextargs.Context) ([]string, error) {
	if len(request.ports) == 1 {
		// no need to check if port is open or not
		return request.ports, nil
	}
	errs := []error{}
	// if more than 1 port is provided, check if port is open or not
	openPorts := make([]string, 0)
	for _, port := range request.ports {
		cloned := target.Clone()
		if err := cloned.UseNetworkPort(port, request.ExcludePorts); err != nil {
			errs = append(errs, err)
			continue
		}
		addr, err := getAddress(cloned.MetaInput.Input)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		conn, err := protocolstate.Dialer.Dial(target.Context(), "tcp", addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_ = conn.Close()
		openPorts = append(openPorts, port)
	}
	if len(openPorts) == 0 {
		return nil, multierr.Combine(errs...)
	}
	return openPorts, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(target *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	visitedAddresses := make(mapsutil.Map[string, struct{}])

	if request.Port == "" {
		// backwords compatibility or for other use cases
		// where port is not provided in template
		if err := request.executeOnTarget(target, visitedAddresses, metadata, previous, callback); err != nil {
			return err
		}
	}

	// get open ports from list of ports provided in template
	ports, err := request.getOpenPorts(target)
	if len(ports) == 0 {
		return err
	}
	if err != nil {
		// TODO: replace this after scan context is implemented
		gologger.Verbose().Msgf("[%v] got errors while checking open ports: %s\n", request.options.TemplateID, err)
	}

	// stop at first match if requested
	atomicBool := &atomic.Bool{}
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if event != nil && event.HasOperatorResult() {
			atomicBool.Store(true)
		}
		callback(event)
	}

	for _, port := range ports {
		input := target.Clone()
		// use network port updates input with new port requested in template file
		// and it is ignored if input port is not standard http(s) ports like 80,8080,8081 etc
		// idea is to reduce redundant dials to http ports
		if err := input.UseNetworkPort(port, request.ExcludePorts); err != nil {
			gologger.Debug().Msgf("Could not network port from constants: %s\n", err)
		}
		if err := request.executeOnTarget(input, visitedAddresses, metadata, previous, wrappedCallback); err != nil {
			return err
		}
		if shouldStopAtFirstMatch && atomicBool.Load() {
			break
		}
	}

	return nil
}

func (request *Request) executeOnTarget(input *contextargs.Context, visited mapsutil.Map[string, struct{}], metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var address string
	var err error
	if request.isUnresponsiveAddress(input) {
		// skip on unresponsive address no need to continue
		return nil
	}

	if request.SelfContained {
		address = ""
	} else {
		address, err = getAddress(input.MetaInput.Input)
	}
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not get address from url")
	}
	variables := protocolutils.GenerateVariables(address, false, nil)
	// add template ctx variables to varMap
	if request.options.HasTemplateCtx(input.MetaInput) {
		variables = generators.MergeMaps(variables, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	variablesMap := request.options.Variables.Evaluate(variables)
	variables = generators.MergeMaps(variablesMap, variables, request.options.Constants)

	// stop at first match if requested
	atomicBool := &atomic.Bool{}
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if event != nil && event.HasOperatorResult() {
			atomicBool.Store(true)
		}
		callback(event)
	}

	for _, kv := range request.addresses {
		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		actualAddress := replacer.Replace(kv.address, variables)

		if visited.Has(actualAddress) && !request.options.Options.DisableClustering {
			continue
		}
		visited.Set(actualAddress, struct{}{})
		if err = request.executeAddress(variables, actualAddress, address, input, kv.tls, previous, wrappedCallback); err != nil {
			outputEvent := request.responseToDSLMap("", "", "", address, "")
			callback(&output.InternalWrappedEvent{InternalEvent: outputEvent})
			gologger.Warning().Msgf("[%v] Could not make network request for (%s) : %s\n", request.options.TemplateID, actualAddress, err)
		}
		if shouldStopAtFirstMatch && atomicBool.Load() {
			break
		}
	}
	return err
}

// executeAddress executes the request for an address
func (request *Request) executeAddress(variables map[string]interface{}, actualAddress, address string, input *contextargs.Context, shouldUseTLS bool, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	variables = generators.MergeMaps(variables, map[string]interface{}{"Hostname": address})
	payloads := generators.BuildPayloadFromOptions(request.options.Options)

	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return err
	}
	updatedTarget := input.Clone()
	updatedTarget.MetaInput.Input = actualAddress

	// if request threads matches global payload concurrency we follow it
	shouldFollowGlobal := request.Threads == request.options.Options.PayloadConcurrency

	if request.generator != nil {
		iterator := request.generator.NewIterator()
		var multiErr error
		m := &sync.Mutex{}
		swg, err := syncutil.New(syncutil.WithSize(request.Threads))
		if err != nil {
			return err
		}

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
					m.Lock()
					multiErr = multierr.Append(multiErr, err)
					m.Unlock()
				}
			}
			if request.isUnresponsiveAddress(updatedTarget) {
				// skip on unresponsive address no need to continue
				return nil
			}

			value = generators.MergeMaps(value, payloads)
			swg.Add()
			go func(vars map[string]interface{}) {
				defer swg.Done()
				if request.isUnresponsiveAddress(updatedTarget) {
					// skip on unresponsive address no need to continue
					return
				}
				if err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, vars, previous, callback); err != nil {
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
		value := maps.Clone(payloads)
		if err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

func (request *Request) executeRequestWithPayloads(variables map[string]interface{}, actualAddress, address string, input *contextargs.Context, shouldUseTLS bool, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var (
		hostname string
		conn     net.Conn
		err      error
	)
	if host, _, err := net.SplitHostPort(actualAddress); err == nil {
		hostname = host
	}
	updatedTarget := input.Clone()
	updatedTarget.MetaInput.Input = actualAddress

	if request.isUnresponsiveAddress(updatedTarget) {
		// skip on unresponsive address no need to continue
		return nil
	}

	if shouldUseTLS {
		conn, err = request.dialer.DialTLS(input.Context(), "tcp", actualAddress)
	} else {
		conn, err = request.dialer.Dial(input.Context(), "tcp", actualAddress)
	}
	// adds it to unresponsive address list if applicable
	request.markHostError(updatedTarget, err)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(request.options.Options.Timeout) * time.Second))

	var interactshURLs []string

	var responseBuilder, reqBuilder strings.Builder

	interimValues := generators.MergeMaps(variables, payloads)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Network Protocol request variables: %s\n", vardump.DumpVariables(interimValues))
	}

	inputEvents := make(map[string]interface{})

	for _, input := range request.Inputs {
		dataInBytes := []byte(input.Data)
		var err error

		dataInBytes, err = expressions.EvaluateByte(dataInBytes, interimValues)
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not evaluate template expressions")
		}

		data := string(dataInBytes)
		if request.options.Interactsh != nil {
			data, interactshURLs = request.options.Interactsh.Replace(data, []string{})
			dataInBytes = []byte(data)
		}

		reqBuilder.Write(dataInBytes)

		if err := expressions.ContainsUnresolvedVariables(data); err != nil {
			gologger.Warning().Msgf("[%s] Could not make network request for %s: %v\n", request.options.TemplateID, actualAddress, err)
			return nil
		}

		if input.Type.GetType() == hexType {
			dataInBytes, err = hex.DecodeString(data)
			if err != nil {
				request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
				request.options.Progress.IncrementFailedRequestsBy(1)
				return errors.Wrap(err, "could not write request to server")
			}
		}

		if _, err := conn.Write(dataInBytes); err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		if input.Read > 0 {
			buffer, err := ConnReadNWithTimeout(conn, int64(input.Read), request.options.Options.GetTimeouts().TcpReadTimeout)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not read response from connection")
			}

			responseBuilder.Write(buffer)

			bufferStr := string(buffer)
			if input.Name != "" {
				inputEvents[input.Name] = bufferStr
				interimValues[input.Name] = bufferStr
			}

			// Run any internal extractors for the request here and add found values to map.
			if request.CompiledOperators != nil {
				values := request.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{input.Name: bufferStr}, request.Extract)
				for k, v := range values {
					payloads[k] = v
				}
			}
		}
	}

	request.options.Progress.IncrementRequests()

	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		requestBytes := []byte(reqBuilder.String())
		msg := fmt.Sprintf("[%s] Dumped Network request for %s\n%s", request.options.TemplateID, actualAddress, hex.Dump(requestBytes))
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Str("address", actualAddress).Msg(msg)
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(address, request.options.TemplateID, request.Type().String(), msg)
		}
		if request.options.Options.VerboseVerbose {
			gologger.Print().Msgf("\nCompact HEX view:\n%s", hex.EncodeToString(requestBytes))
		}
	}

	request.options.Output.Request(request.options.TemplatePath, actualAddress, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent TCP request to %s", actualAddress)

	bufferSize := 1024
	if request.ReadSize != 0 {
		bufferSize = request.ReadSize
	}
	if request.ReadAll {
		bufferSize = -1
	}

	final, err := ConnReadNWithTimeout(conn, int64(bufferSize), request.options.Options.GetTimeouts().TcpReadTimeout)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		gologger.Verbose().Msgf("could not read more data from %s: %s", actualAddress, err)
	}
	responseBuilder.Write(final)

	response := responseBuilder.String()
	outputEvent := request.responseToDSLMap(reqBuilder.String(), string(final), response, input.MetaInput.Input, actualAddress)
	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	outputEvent["ip"] = request.dialer.GetDialedIP(hostname)
	if request.options.StopAtFirstMatch {
		outputEvent["stop-at-first-match"] = true
	}
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range interimValues {
		outputEvent[k] = v
	}
	for k, v := range inputEvents {
		outputEvent[k] = v
	}
	if request.options.Interactsh != nil {
		request.options.Interactsh.MakePlaceholders(interactshURLs, outputEvent)
	}

	var event *output.InternalWrappedEvent
	if len(interactshURLs) == 0 {
		event = eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(payloads, outputEvent), request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
			wrappedEvent.OperatorsResult.PayloadValues = payloads
		})
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: outputEvent}
		request.options.Interactsh.RequestEvent(interactshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}
	if len(interactshURLs) > 0 {
		event.UsesInteractsh = true
	}

	dumpResponse(event, request, response, actualAddress, address)

	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, request *Request, response string, actualAddress, address string) {
	cliOptions := request.options.Options
	if cliOptions.Debug || cliOptions.DebugResponse || cliOptions.StoreResponse {
		requestBytes := []byte(response)
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, hex.Dump(requestBytes), cliOptions.NoColor, true)
		msg := fmt.Sprintf("[%s] Dumped Network response for %s\n\n", request.options.TemplateID, actualAddress)
		if cliOptions.Debug || cliOptions.DebugResponse {
			gologger.Debug().Msg(fmt.Sprintf("%s%s", msg, highlightedResponse))
		}
		if cliOptions.StoreResponse {
			request.options.Output.WriteStoreDebugData(address, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s%s", msg, hex.Dump(requestBytes)))
		}
		if cliOptions.VerboseVerbose {
			displayCompactHexView(event, response, cliOptions.NoColor)
		}
	}
}

func displayCompactHexView(event *output.InternalWrappedEvent, response string, noColor bool) {
	operatorsResult := event.OperatorsResult
	if operatorsResult != nil {
		var allMatches []string
		for _, namedMatch := range operatorsResult.Matches {
			for _, matchElement := range namedMatch {
				allMatches = append(allMatches, hex.EncodeToString([]byte(matchElement)))
			}
		}
		tempOperatorResult := &operators.Result{Matches: map[string][]string{"matchesInHex": allMatches}}
		gologger.Print().Msgf("\nCompact HEX view:\n%s", responsehighlighter.Highlight(tempOperatorResult, hex.EncodeToString([]byte(response)), noColor, false))
	}
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if strings.Contains(toTest, "://") {
		parsed, err := url.Parse(toTest)
		if err != nil {
			return "", err
		}
		toTest = parsed.Host
	}
	return toTest, nil
}

func ConnReadNWithTimeout(conn net.Conn, n int64, timeout time.Duration) ([]byte, error) {
	if n == -1 {
		// if n is -1 then read all available data from connection
		return reader.ConnReadNWithTimeout(conn, -1, timeout)
	} else if n == 0 {
		n = 4096 // default buffer size
	}
	b := make([]byte, n)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	count, err := conn.Read(b)
	_ = conn.SetDeadline(time.Time{})
	if err != nil && os.IsTimeout(err) && count > 0 {
		// in case of timeout with some value read, return the value
		return b[:count], nil
	}
	if err != nil {
		return nil, err
	}
	return b[:count], nil
}

// markHostError checks if the error is a unreponsive host error and marks it
func (request *Request) markHostError(input *contextargs.Context, err error) {
	if request.options.HostErrorsCache != nil {
		request.options.HostErrorsCache.MarkFailedOrRemove(request.options.ProtocolType.String(), input, err)
	}
}

// isUnresponsiveAddress checks if the error is a unreponsive based on its execution history
func (request *Request) isUnresponsiveAddress(input *contextargs.Context) bool {
	if request.options.HostErrorsCache != nil {
		return request.options.HostErrorsCache.Check(request.options.ProtocolType.String(), input)
	}
	return false
}
