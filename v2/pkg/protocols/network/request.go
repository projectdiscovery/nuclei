package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata output.InternalEvent) ([]*output.InternalWrappedEvent, error) {
	address, err := getAddress(input)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "network", err)
		r.options.Progress.DecrementRequests(1)
		return nil, errors.Wrap(err, "could not get address from url")
	}

	// Compile each request for the template based on the URL
	actualAddress, err := r.Make(address)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.DecrementRequests(1)
		return nil, errors.Wrap(err, "could not build request")
	}

	conn, err := r.dialer.Dial(context.Background(), "tcp", actualAddress)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.DecrementRequests(1)
		return nil, errors.Wrap(err, "could not connect to server request")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	reqBuilder := &strings.Builder{}
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
			return nil, errors.Wrap(err, "could not write request to server")
		}
		reqBuilder.Grow(len(input.Data))
		reqBuilder.WriteString(input.Data)

		_, err = conn.Write(data)
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, address, "network", err)
			r.options.Progress.DecrementRequests(1)
			return nil, errors.Wrap(err, "could not write request to server")
		}
		r.options.Progress.IncrementRequests()
	}
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, address, "network", err)
		r.options.Progress.DecrementRequests(1)
		return nil, errors.Wrap(err, "could not write request to server")
	}

	if r.options.Options.Debug {
		gologger.Info().Str("address", actualAddress).Msgf("[%s] Dumped Network request for %s", r.options.TemplateID, actualAddress)
		fmt.Fprintf(os.Stderr, "%s\n", reqBuilder.String())
	}

	r.options.Output.Request(r.options.TemplateID, actualAddress, "network", err)
	gologger.Verbose().Msgf("[%s] Sent Network request to %s", r.options.TemplateID, actualAddress)

	bufferSize := 1024
	if r.ReadSize != 0 {
		bufferSize = r.ReadSize
	}
	buffer := make([]byte, bufferSize)
	n, _ := conn.Read(buffer)
	resp := string(buffer[:n])

	if r.options.Options.Debug {
		gologger.Debug().Msgf("[%s] Dumped Network response for %s", r.options.TemplateID, actualAddress)
		fmt.Fprintf(os.Stderr, "%s\n", resp)
	}
	ouputEvent := r.responseToDSLMap(reqBuilder.String(), resp, input, actualAddress)

	event := []*output.InternalWrappedEvent{{InternalEvent: ouputEvent}}
	if r.CompiledOperators != nil {
		result, ok := r.Operators.Execute(ouputEvent, r.Match, r.Extract)
		if !ok {
			return nil, nil
		}
		event[0].OperatorsResult = result
	}
	return event, nil
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
