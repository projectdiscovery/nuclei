package file

import (
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg := sizedwaitgroup.New(request.options.Options.BulkSize)

	err := request.getInputPaths(input, func(data string) {
		wg.Add()

		go func(filePath string) {
			defer wg.Done()

			file, err := os.Open(filePath)
			if err != nil {
				gologger.Error().Msgf("Could not open file path %s: %s\n", filePath, err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				gologger.Error().Msgf("Could not stat file path %s: %s\n", filePath, err)
				return
			}
			if stat.Size() >= int64(request.MaxSize) {
				gologger.Verbose().Msgf("Could not process path %s: exceeded max size\n", filePath)
				return
			}

			buffer, err := ioutil.ReadAll(file)
			if err != nil {
				gologger.Error().Msgf("Could not read file path %s: %s\n", filePath, err)
				return
			}
			dataStr := tostring.UnsafeToString(buffer)

			gologger.Verbose().Msgf("[%s] Sent FILE request to %s", request.options.TemplateID, filePath)
			outputEvent := request.responseToDSLMap(dataStr, input, filePath)
			for k, v := range previous {
				outputEvent[k] = v
			}

			event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

			if request.options.Options.Debug || request.options.Options.DebugResponse {
				gologger.Info().Msgf("[%s] Dumped file request for %s", request.options.TemplateID, filePath)
				gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, dataStr, request.options.Options.NoColor))
			}

			callback(event)
		}(data)
	})
	wg.Wait()
	if err != nil {
		request.options.Output.Request(request.options.TemplateID, input, "file", err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	request.options.Progress.IncrementRequests()
	return nil
}
