package offlinehttp

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

const maxSize = 5 * 1024 * 1024

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HTTPProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg := sizedwaitgroup.New(request.options.Options.BulkSize)

	err := request.getInputPaths(input, func(data string) {
		wg.Add()

		go func(data string) {
			defer wg.Done()

			file, err := os.Open(data)
			if err != nil {
				gologger.Error().Msgf("Could not open file path %s: %s\n", data, err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				gologger.Error().Msgf("Could not stat file path %s: %s\n", data, err)
				return
			}
			if stat.Size() >= int64(maxSize) {
				gologger.Verbose().Msgf("Could not process path %s: exceeded max size\n", data)
				return
			}

			buffer, err := ioutil.ReadAll(file)
			if err != nil {
				gologger.Error().Msgf("Could not read file path %s: %s\n", data, err)
				return
			}
			dataStr := tostring.UnsafeToString(buffer)

			resp, err := readResponseFromString(dataStr)
			if err != nil {
				gologger.Error().Msgf("Could not read raw response %s: %s\n", data, err)
				return
			}

			if request.options.Options.Debug || request.options.Options.DebugRequests {
				gologger.Info().Msgf("[%s] Dumped offline-http request for %s", request.options.TemplateID, data)
				gologger.Print().Msgf("%s", dataStr)
			}
			gologger.Verbose().Msgf("[%s] Sent OFFLINE-HTTP request to %s", request.options.TemplateID, data)

			dumpedResponse, err := httputil.DumpResponse(resp, true)
			if err != nil {
				gologger.Error().Msgf("Could not dump raw http response %s: %s\n", data, err)
				return
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				gologger.Error().Msgf("Could not read raw http response body %s: %s\n", data, err)
				return
			}

			outputEvent := request.responseToDSLMap(resp, data, data, data, tostring.UnsafeToString(dumpedResponse), tostring.UnsafeToString(body), headersToString(resp.Header), 0, nil)
			outputEvent["ip"] = ""
			for k, v := range previous {
				outputEvent[k] = v
			}

			event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
			callback(event)
		}(data)
	})
	wg.Wait()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input, "file", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	request.options.Progress.IncrementRequests()
	return nil
}

// headersToString converts http headers to string
func headersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)

			if i != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}
