package file

import (
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg := sizedwaitgroup.New(r.options.Options.BulkSize)

	err := r.getInputPaths(input, func(data string) {
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
			if stat.Size() >= int64(r.MaxSize) {
				gologger.Verbose().Msgf("Could not process path %s: exceeded max size\n", filePath)
				return
			}

			buffer, err := ioutil.ReadAll(file)
			if err != nil {
				gologger.Error().Msgf("Could not read file path %s: %s\n", filePath, err)
				return
			}
			dataStr := tostring.UnsafeToString(buffer)

			gologger.Verbose().Msgf("[%s] Sent FILE request to %s", r.options.TemplateID, filePath)
			outputEvent := r.responseToDSLMap(dataStr, input, filePath)
			for k, v := range previous {
				outputEvent[k] = v
			}

			event := createEvent(r, outputEvent)

			if r.options.Options.Debug || r.options.Options.DebugResponse {
				gologger.Info().Msgf("[%s] Dumped file request for %s", r.options.TemplateID, filePath)
				gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, dataStr, r.options.Options.NoColor))
			}

			callback(event)
		}(data)
	})
	wg.Wait()
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "file", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	r.options.Progress.IncrementRequests()
	return nil
}

func createEvent(request *Request, outputEvent output.InternalEvent) *output.InternalWrappedEvent {
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}

	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(outputEvent, request.Match, request.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = request.MakeResultEvent(event)
		}
	}

	return event
}
