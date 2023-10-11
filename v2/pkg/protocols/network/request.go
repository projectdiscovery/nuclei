package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.NetworkProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(target *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var address string
	var err error

	input := target.Clone()
	// use network port updates input with new port requested in template file
	// and it is ignored if input port is not standard http(s) ports like 80,8080,8081 etc
	// idea is to reduce redundant dials to http ports
	if err := input.UseNetworkPort(request.Port, request.ExcludePorts); err != nil {
		gologger.Debug().Msgf("Could not network port from constants: %s\n", err)
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
	variablesMap := request.options.Variables.Evaluate(variables)
	variables = generators.MergeMaps(variablesMap, variables, request.options.Constants)

	visitedAddresses := make(mapsutil.Map[string, struct{}])

	for _, kv := range request.addresses {
		actualAddress := replacer.Replace(kv.address, variables)

		if visitedAddresses.Has(actualAddress) && !request.options.Options.DisableClustering {
			continue
		}
		visitedAddresses.Set(actualAddress, struct{}{})

		if err := request.executeAddress(variables, actualAddress, address, input.MetaInput.Input, kv.tls, previous, callback); err != nil {
			outputEvent := request.responseToDSLMap("", "", "", address, "")
			callback(&output.InternalWrappedEvent{InternalEvent: outputEvent})
			gologger.Warning().Msgf("[%v] Could not make network request for (%s) : %s\n", request.options.TemplateID, actualAddress, err)
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (request *Request) executeAddress(variables map[string]interface{}, actualAddress, address, input string, shouldUseTLS bool, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	variables = generators.MergeMaps(variables, map[string]interface{}{"Hostname": address})
	payloads := generators.BuildPayloadFromOptions(request.options.Options)

	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return err
	}

	if request.generator != nil {
		iterator := request.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			value = generators.MergeMaps(value, payloads)
			if err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(payloads)
		if err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

func (request *Request) executeRequestWithPayloads(variables map[string]interface{}, actualAddress, address, input string, shouldUseTLS bool, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var (
		hostname string
		conn     net.Conn
		err      error
	)
	if host, _, err := net.SplitHostPort(actualAddress); err == nil {
		hostname = host
	}

	if shouldUseTLS {
		conn, err = request.dialer.DialTLS(context.Background(), "tcp", actualAddress)
	} else {
		conn, err = request.dialer.Dial(context.Background(), "tcp", actualAddress)
	}
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
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(interimValues))
	}

	inputEvents := make(map[string]interface{})

	for _, input := range request.Inputs {
		data := []byte(input.Data)

		if request.options.Interactsh != nil {
			var transformedData string
			transformedData, interactshURLs = request.options.Interactsh.Replace(string(data), []string{})
			data = []byte(transformedData)
		}

		finalData, err := expressions.EvaluateByte(data, interimValues)
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not evaluate template expressions")
		}

		reqBuilder.Write(finalData)

		if err := expressions.ContainsUnresolvedVariables(string(finalData)); err != nil {
			gologger.Warning().Msgf("[%s] Could not make network request for %s: %v\n", request.options.TemplateID, actualAddress, err)
			return nil
		}

		if input.Type.GetType() == hexType {
			finalData, err = hex.DecodeString(string(finalData))
			if err != nil {
				request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
				request.options.Progress.IncrementFailedRequestsBy(1)
				return errors.Wrap(err, "could not write request to server")
			}
		}

		if _, err := conn.Write(finalData); err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		if input.Read > 0 {
			buffer := make([]byte, input.Read)
			n, err := conn.Read(buffer)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not read response from connection")
			}

			responseBuilder.Write(buffer[:n])

			bufferStr := string(buffer[:n])
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

	var (
		final []byte
		n     int
	)

	if request.ReadAll {
		readInterval := time.NewTimer(time.Second * 1)
		// stop the timer and drain the channel
		closeTimer := func(t *time.Timer) {
			if !t.Stop() {
				<-t.C
			}
		}
	readSocket:
		for {
			select {
			case <-readInterval.C:
				closeTimer(readInterval)
				break readSocket
			default:
				buf := make([]byte, bufferSize)
				nBuf, err := conn.Read(buf)
				if err != nil && !os.IsTimeout(err) && err != io.EOF {
					request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
					closeTimer(readInterval)
					return errors.Wrap(err, "could not read from server")
				}
				responseBuilder.Write(buf[:nBuf])
				final = append(final, buf...)
				n += nBuf
			}
		}
	} else {
		final = make([]byte, bufferSize)
		n, err = conn.Read(final)
		if err != nil && !os.IsTimeout(err) && err != io.EOF {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			return errors.Wrap(err, "could not read from server")
		}
		responseBuilder.Write(final[:n])
	}

	response := responseBuilder.String()
	outputEvent := request.responseToDSLMap(reqBuilder.String(), string(final[:n]), response, input, actualAddress)
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
