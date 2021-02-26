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
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "network", err)
		r.options.Progress.DecrementRequests(1)
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
			gologger.Verbose().Lable("ERR").Msgf("Could not make network request for %s: %s\n", actualAddress, err)
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
		r.options.Progress.DecrementRequests(1)
		return err
	}

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
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not connect to server request")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(r.options.Options.Timeout) * time.Second))

	responseBuilder := &strings.Builder{}
	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, input := range r.Inputs {
		var data []byte

		switch input.Type {
		case "hex":
			data, err = hex.DecodeString(input.Data)
		default:
			data = []byte(input.Data)
		}
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", err)
			r.options.Progress.DecrementRequests(1)
			return errors.Wrap(err, "could not write request to server")
		}
		reqBuilder.Grow(len(input.Data))
		reqBuilder.WriteString(input.Data)

		_, err = conn.Write(data)
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", err)
			r.options.Progress.DecrementRequests(1)
			return errors.Wrap(err, "could not write request to server")
		}

		if input.Read > 0 {
			buffer := make([]byte, input.Read)
			n, _ := conn.Read(buffer)
			responseBuilder.Write(buffer[:n])
			if input.Name != "" {
				inputEvents[input.Name] = string(buffer[:n])
			}
		}
		r.options.Progress.IncrementRequests()
	}
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not write request to server")
	}

	if r.options.Options.Debug || r.options.Options.DebugRequests {
		gologger.Info().Str("address", actualAddress).Msgf("[%s] Dumped Network request for %s", r.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s", reqBuilder.String())
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
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not read from server")
	}
	responseBuilder.Write(final[:n])

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped Network response for %s", r.options.TemplateID, actualAddress)
		gologger.Print().Msgf("%s", responseBuilder.String())
	}
	outputEvent := r.responseToDSLMap(reqBuilder.String(), string(final[:n]), responseBuilder.String(), input, actualAddress)
	outputEvent["ip"] = r.dialer.GetDialedIP(hostname)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range inputEvents {
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
