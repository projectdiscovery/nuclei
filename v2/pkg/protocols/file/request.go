package file

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
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

			event := createEvent(r, filePath, dataStr, outputEvent)
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

// TODO extract duplicated code
func createEvent(request *Request, filePath string, response string, outputEvent output.InternalEvent) *output.InternalWrappedEvent {
	debugResponse := func(data string) {
		if request.options.Options.Debug || request.options.Options.DebugResponse {
			gologger.Info().Msgf("[%s] Dumped file request for %s", request.options.TemplateID, filePath)
			gologger.Print().Msgf("%s", data)
		}
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if request.CompiledOperators != nil {

		matcher := func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
			isMatch, matched := request.Match(data, matcher)
			var result = response

			if len(matched) != 0 {
				if !request.options.Options.NoColor {
					colorizer := aurora.NewAurora(true)
					for _, currentMatch := range matched {
						result = strings.ReplaceAll(result, currentMatch, colorizer.Green(currentMatch).String())
					}
				}
				debugResponse(result)
			}

			return isMatch, matched
		}

		result, ok := request.CompiledOperators.Execute(outputEvent, matcher, request.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = request.MakeResultEvent(event)
		}
	} else {
		debugResponse(response)
	}
	return event
}
