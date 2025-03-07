package offlinehttp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/utils/conversion"
	syncutil "github.com/projectdiscovery/utils/sync"
	unitutils "github.com/projectdiscovery/utils/unit"
)

var _ protocols.Request = &Request{}

const maxSize = 5 * unitutils.Mega

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.OfflineHTTPProtocol
}

// RawInputMode is a flag to indicate if the input is raw input
// rather than a file path
var RawInputMode = false

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if RawInputMode {
		return request.executeRawInput(input.MetaInput.Input, "", input, callback)
	}

	wg, err := syncutil.New(syncutil.WithSize(request.options.Options.BulkSize))
	if err != nil {
		return err
	}

	err = request.getInputPaths(input.MetaInput.Input, func(data string) {
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

			buffer, err := io.ReadAll(file)
			if err != nil {
				gologger.Error().Msgf("Could not read file path %s: %s\n", data, err)
				return
			}
			dataStr := conversion.String(buffer)

			if err := request.executeRawInput(dataStr, data, input, callback); err != nil {
				gologger.Error().Msgf("Could not execute raw input %s: %s\n", data, err)
				return
			}
		}(data)
	})
	wg.Wait()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, "file", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	request.options.Progress.IncrementRequests()
	return nil
}

func (request *Request) executeRawInput(data, inputString string, input *contextargs.Context, callback protocols.OutputEventCallback) error {
	resp, err := readResponseFromString(data)
	if err != nil {
		return errors.Wrap(err, "could not read raw response")
	}

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Info().Msgf("[%s] Dumped offline-http request for %s", request.options.TemplateID, data)
		gologger.Print().Msgf("%s", data)
	}
	gologger.Verbose().Msgf("[%s] Sent OFFLINE-HTTP request to %s", request.options.TemplateID, data)

	dumpedResponse, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return errors.Wrap(err, "could not dump raw http response")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "could not read raw http response body")
	}
	reqURL := inputString
	if inputString == "" {
		reqURL = getURLFromRequest(resp.Request)
	}

	outputEvent := request.responseToDSLMap(resp, data, reqURL, data, conversion.String(dumpedResponse), conversion.String(body), utils.HeadersToString(resp.Header), 0, nil)
	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.GetID(), outputEvent)
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	outputEvent["ip"] = ""

	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
	callback(event)
	return nil
}

func getURLFromRequest(req *http.Request) string {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
}
