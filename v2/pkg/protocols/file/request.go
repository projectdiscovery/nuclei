package file

import (
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/remeh/sizedwaitgroup"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg := sizedwaitgroup.New(r.options.Options.BulkSize)

	err := r.getInputPaths(input, func(data string) {
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
			if stat.Size() >= int64(r.MaxSize) {
				gologger.Verbose().Msgf("Could not process path %s: exceeded max size\n", data)
				return
			}

			buffer, err := ioutil.ReadAll(file)
			if err != nil {
				gologger.Error().Msgf("Could not read file path %s: %s\n", data, err)
				return
			}
			dataStr := tostring.UnsafeToString(buffer)
			if r.options.Options.Debug || r.options.Options.DebugRequests {
				gologger.Info().Msgf("[%s] Dumped file request for %s", r.options.TemplateID, data)
				gologger.Print().Msgf("%s", dataStr)
			}
			gologger.Verbose().Msgf("[%s] Sent FILE request to %s", r.options.TemplateID, data)
			outputEvent := r.responseToDSLMap(dataStr, input, data)
			for k, v := range previous {
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
