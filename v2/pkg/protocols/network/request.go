package network

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
)

var _ protocols.Request = &Request{}

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
		request.options.Output.Request(request.options.TemplateID, input, "network", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not get address from url")
	}

	for _, kv := range request.addresses {
		actualAddress := replacer.Replace(kv.ip, map[string]interface{}{"Hostname": address})
		if kv.port != "" {
			if strings.Contains(address, ":") {
				actualAddress, _, _ = net.SplitHostPort(actualAddress)
			}
			actualAddress = net.JoinHostPort(actualAddress, kv.port)
		}
		if input != "" {
			input = actualAddress
		}

		if err := request.executeAddress(actualAddress, address, input, kv.tls, previous, callback); err != nil {
			gologger.Verbose().Label("ERR").Msgf("Could not make network request for %s: %s\n", actualAddress, err)
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (request *Request) executeAddress(actualAddress, address, input string, shouldUseTLS bool, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		request.options.Output.Request(request.options.TemplateID, address, "network", err)
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
			if err := request.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := generators.MergeMaps(map[string]interface{}{}, payloads)
		if err := request.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

func (request *Request) executeRequestWithPayloads(actualAddress, address, input string, shouldUseTLS bool, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var (
		hostname string
		conn     net.Conn
		err      error
	)

	request.dynamicValues = generators.MergeMaps(payloads, map[string]interface{}{"Hostname": address})

	if host, _, splitErr := net.SplitHostPort(actualAddress); splitErr == nil {
		hostname = host
	}

	if shouldUseTLS {
		conn, err = request.dialer.DialTLS(context.Background(), "tcp", actualAddress)
	} else {
		conn, err = request.dialer.Dial(context.Background(), "tcp", actualAddress)
	}
	if err != nil {
		request.options.Output.Request(request.options.TemplateID, address, "network", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server request")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(request.options.Options.Timeout) * time.Second))

	hasInteractMarkers := interactsh.HasMatchers(request.CompiledOperators)
	var interactURL string
	if request.options.Interactsh != nil && hasInteractMarkers {
		interactURL = request.options.Interactsh.URL()
	}

	responseBuilder := &strings.Builder{}
	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, input := range request.Inputs {
		var data []byte

		switch input.Type {
		case "hex":
			data, err = hex.DecodeString(input.Data)
		default:
			if interactURL != "" {
				input.Data = request.options.Interactsh.ReplaceMarkers(input.Data, interactURL)
			}
			data = []byte(input.Data)
		}
		if err != nil {
			request.options.Output.Request(request.options.TemplateID, address, "network", err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}
		reqBuilder.Grow(len(input.Data))

		finalData, dataErr := expressions.EvaluateByte(data, payloads)
		if dataErr != nil {
			request.options.Output.Request(request.options.TemplateID, address, "network", dataErr)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, "could not evaluate template expressions")
		}
		reqBuilder.Write(finalData)

		if varErr := expressions.ContainsUnresolvedVariables(string(finalData)); varErr != nil {
			gologger.Warning().Msgf("[%s] Could not make network request for %s: %v\n", request.options.TemplateID, actualAddress, varErr)
			return nil
		}
		if _, err := conn.Write(finalData); err != nil {
			request.options.Output.Request(request.options.TemplateID, address, "network", err)
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
		requestOutput := reqBuilder.String()
		gologger.Info().Str("address", actualAddress).Msgf("[%s] Dumped Network request for %s", request.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s\nHex: %s", requestOutput, hex.EncodeToString([]byte(requestOutput)))
	}

	request.options.Output.Request(request.options.TemplateID, actualAddress, "network", err)
	gologger.Verbose().Msgf("Sent TCP request to %s", actualAddress)

	bufferSize := 1024
	if request.ReadSize != 0 {
		bufferSize = request.ReadSize
	}
	final := make([]byte, bufferSize)
	n, err := conn.Read(final)
	if err != nil && err != io.EOF {
		request.options.Output.Request(request.options.TemplateID, address, "network", err)
		return errors.Wrap(err, "could not read from server")
	}
	responseBuilder.Write(final[:n])

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
	if interactURL == "" {
		event = eventcreator.CreateEventWithAdditionalOptions(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
			wrappedEvent.OperatorsResult.PayloadValues = payloads
		})
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: outputEvent}
		request.options.Interactsh.RequestEvent(interactURL, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}

	if request.options.Options.Debug || request.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped Network response for %s", request.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s\nHex: %s", response, responsehighlighter.Highlight(event.OperatorsResult, hex.EncodeToString([]byte(response)), request.options.Options.NoColor))
	}

	return nil
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
