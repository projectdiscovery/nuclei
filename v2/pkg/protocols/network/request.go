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
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "network", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not get address from url")
	}

	for _, kv := range r.addresses {
		actualAddress := replacer.Replace(kv.ip, map[string]interface{}{"Hostname": address})
		if kv.port != "" {
			if strings.Contains(address, ":") {
				actualAddress, _, _ = net.SplitHostPort(actualAddress)
			}
			actualAddress = net.JoinHostPort(actualAddress, kv.port)
		}

		err = r.executeAddress(actualAddress, address, input, kv.tls, previous, callback)
		if err != nil {
			gologger.Verbose().Label("ERR").Msgf("Could not make network request for %s: %s\n", actualAddress, err)
			continue
		}
	}
	return nil
}

// executeAddress executes the request for an address
func (r *Request) executeAddress(actualAddress, address, input string, shouldUseTLS bool, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return err
	}

	if r.generator != nil {
		iterator := r.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			if err := r.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := make(map[string]interface{})
		if err := r.executeRequestWithPayloads(actualAddress, address, input, shouldUseTLS, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

func (r *Request) executeRequestWithPayloads(actualAddress, address, input string, shouldUseTLS bool, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	var (
		hostname string
		conn     net.Conn
		err      error
	)

	if host, _, splitErr := net.SplitHostPort(actualAddress); splitErr == nil {
		hostname = host
	}

	if shouldUseTLS {
		conn, err = r.dialer.DialTLS(context.Background(), "tcp", actualAddress)
	} else {
		conn, err = r.dialer.Dial(context.Background(), "tcp", actualAddress)
	}
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server request")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(r.options.Options.Timeout) * time.Second))

	hasInteractMarkers := interactsh.HasMatchers(r.CompiledOperators)
	var interactURL string
	if r.options.Interactsh != nil && hasInteractMarkers {
		interactURL = r.options.Interactsh.URL()
	}

	responseBuilder := &strings.Builder{}
	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, input := range r.Inputs {
		var data []byte

		switch input.Type {
		case "hex":
			data, err = hex.DecodeString(input.Data)
		default:
			if interactURL != "" {
				input.Data = r.options.Interactsh.ReplaceMarkers(input.Data, interactURL)
			}
			data = []byte(input.Data)
		}
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", err)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}
		reqBuilder.Grow(len(input.Data))

		finalData, dataErr := expressions.EvaluateByte(data, payloads)
		if dataErr != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", dataErr)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, "could not evaluate template expressions")
		}
		reqBuilder.Write(finalData)

		_, err = conn.Write(finalData)
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", err)
			r.options.Progress.IncrementFailedRequestsBy(1)
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
			if r.CompiledOperators != nil {
				values := r.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{input.Name: bufferStr}, r.Extract)
				for k, v := range values {
					payloads[k] = v
				}
			}
		}
	}
	r.options.Progress.IncrementRequests()

	if r.options.Options.Debug || r.options.Options.DebugRequests {
		requestOutput := reqBuilder.String()
		gologger.Info().Str("address", actualAddress).Msgf("[%s] Dumped Network request for %s", r.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s\nHex: %s", requestOutput, hex.EncodeToString([]byte(requestOutput)))
	}

	r.options.Output.Request(r.options.TemplateID, actualAddress, "network", err)
	gologger.Verbose().Msgf("Sent TCP request to %s", actualAddress)

	bufferSize := 1024
	if r.ReadSize != 0 {
		bufferSize = r.ReadSize
	}
	final := make([]byte, bufferSize)
	n, err := conn.Read(final)
	if err != nil && err != io.EOF {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		return errors.Wrap(err, "could not read from server")
	}
	responseBuilder.Write(final[:n])

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		responseOutput := responseBuilder.String()
		gologger.Debug().Msgf("[%s] Dumped Network response for %s", r.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s\nHex: %s", responseOutput, hex.EncodeToString([]byte(responseOutput)))
	}
	outputEvent := r.responseToDSLMap(reqBuilder.String(), string(final[:n]), responseBuilder.String(), input, actualAddress)
	outputEvent["ip"] = r.dialer.GetDialedIP(hostname)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range payloads {
		outputEvent[k] = v
	}
	for k, v := range inputEvents {
		outputEvent[k] = v
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if interactURL == "" {
		if r.CompiledOperators != nil {
			result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
			if ok && result != nil {
				event.OperatorsResult = result
				event.OperatorsResult.PayloadValues = payloads
				event.Results = r.MakeResultEvent(event)
			}
		}
		callback(event)
	} else if r.options.Interactsh != nil {
		r.options.Interactsh.RequestEvent(interactURL, &interactsh.RequestData{
			MakeResultFunc: r.MakeResultEvent,
			Event:          event,
			Operators:      r.CompiledOperators,
			MatchFunc:      r.Match,
			ExtractFunc:    r.Extract,
		})
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
