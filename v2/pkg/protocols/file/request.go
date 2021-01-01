package file

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
)

var _ protocols.Request = &Request{}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, metadata output.InternalEvent, callback protocols.OutputEventCallback) error {
	err := r.getInputPaths(input, func(data string) {
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

		if r.options.Options.Debug {
			gologger.Info().Msgf("[%s] Dumped file request for %s", r.options.TemplateID, data)
			fmt.Fprintf(os.Stderr, "%s\n", dataStr)
		}
		gologger.Verbose().Msgf("[%s] Sent file request to %s", r.options.TemplateID, data)
		ouputEvent := r.responseToDSLMap(dataStr, input, data)

		event := &output.InternalWrappedEvent{InternalEvent: ouputEvent}
		if r.CompiledOperators != nil {
			result, ok := r.Operators.Execute(ouputEvent, r.Match, r.Extract)
			if !ok {
				return
			}
			event.OperatorsResult = result
			callback(event)
		}
	})
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "file", err)
		r.options.Progress.DecrementRequests(1)
		return errors.Wrap(err, "could not send file request")
	}
	r.options.Progress.IncrementRequests()
	return nil
}
