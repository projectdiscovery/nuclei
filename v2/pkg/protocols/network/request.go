package network

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.NetworkProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var address string
	var err error

	if request.SelfContained {
		address = ""
	} else {
		address, err = getAddress(input)
	}
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not get address from url")
	}

	for _, kv := range request.addresses {
		variables := generateNetworkVariables(address)
		actualAddress := replacer.Replace(kv.address, variables)

		if err := request.executeAddress(variables, actualAddress, address, input, kv.tls, previous, callback); err != nil {
			gologger.Verbose().Label("ERR").Msgf("Could not make network request for %s: %s\n", actualAddress, err)
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (request *Request) executeAddress(variables map[string]interface{}, actualAddress, address, input string, shouldUseTLS bool, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return err
	}

	payloads := generators.BuildPayloadFromOptions(request.options.Options)

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
		value := generators.CopyMap(payloads)
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

	request.dynamicValues = generators.MergeMaps(payloads, variables)

	if host, _, splitErr := net.SplitHostPort(actualAddress); splitErr == nil {
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
		return errors.Wrap(err, "could not connect to server request")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(request.options.Options.Timeout) * time.Second))

	var interactshURLs []string

	responseBuilder := &strings.Builder{}
	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, input := range request.Inputs {
		var data []byte

		switch input.Type.GetType() {
		case hexType:
			data, err = hex.DecodeString(input.Data)
		default:
			data = []byte(input.Data)
		}
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}
		reqBuilder.Grow(len(input.Data))

		if request.options.Interactsh != nil {
			var transformedData string
			transformedData, interactshURLs = request.options.Interactsh.ReplaceMarkers(string(data), []string{})
			data = []byte(transformedData)
		}

		finalData, dataErr := expressions.EvaluateByte(data, payloads)
		if dataErr != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), dataErr)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, "could not evaluate template expressions")
		}
		reqBuilder.Write(finalData)

		if varErr := expressions.ContainsUnresolvedVariables(string(finalData)); varErr != nil {
			gologger.Warning().Msgf("[%s] Could not make network request for %s: %v\n", request.options.TemplateID, actualAddress, varErr)
			return nil
		}
		if _, err := conn.Write(finalData); err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		if input.Read > 0 {
			buffer := make([]byte, input.Read)
			n, _ := conn.Read(buffer)
			responseBuilder.Write(buffer[:n])

			bufferStr := string(buffer[:n])
			if input.Name != "" {
				inputEvents[input.Name] = bufferStr
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

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		requestBytes := []byte(reqBuilder.String())
		gologger.Debug().Str("address", actualAddress).Msgf("[%s] Dumped Network request for %s\n%s", request.options.TemplateID, actualAddress, hex.Dump(requestBytes))
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
				if err != nil && !os.IsTimeout(err) {
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
		if err != nil && err != io.EOF {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			return errors.Wrap(err, "could not read from server")
		}
		responseBuilder.Write(final[:n])
	}

	response := responseBuilder.String()
	outputEvent := request.responseToDSLMap(reqBuilder.String(), string(final[:n]), response, input, actualAddress)
	outputEvent["ip"] = request.dialer.GetDialedIP(hostname)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range payloads {
		outputEvent[k] = v
	}
	for k, v := range inputEvents {
		outputEvent[k] = v
	}

	var event *output.InternalWrappedEvent
	if len(interactshURLs) == 0 {
		event = eventcreator.CreateEventWithAdditionalOptions(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
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

	dumpResponse(event, request.options, response, actualAddress)

	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, response string, actualAddress string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		requestBytes := []byte(response)
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, hex.Dump(requestBytes), cliOptions.NoColor, true)
		gologger.Debug().Msgf("[%s] Dumped Network response for %s\n\n%s", requestOptions.TemplateID, actualAddress, highlightedResponse)

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

func generateNetworkVariables(input string) map[string]interface{} {
	if !strings.Contains(input, ":") {
		return map[string]interface{}{"Hostname": input, "Host": input}
	}
	host, port, err := net.SplitHostPort(input)
	if err != nil {
		return map[string]interface{}{"Hostname": input}
	}
	return map[string]interface{}{
		"Host":     host,
		"Port":     port,
		"Hostname": input,
	}
}
