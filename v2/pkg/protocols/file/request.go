package file

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.FileProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg := sizedwaitgroup.New(request.options.Options.BulkSize)

	err := request.getInputPaths(input, func(data string) {
		request.options.Progress.AddToTotal(1)
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
			fileContent := tostring.UnsafeToString(buffer)

			gologger.Verbose().Msgf("[%s] Sent FILE request to %s", request.options.TemplateID, filePath)
			outputEvent := request.responseToDSLMap(fileContent, input, filePath)
			for k, v := range previous {
				outputEvent[k] = v
			}

			event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

			dumpResponse(event, request.options, fileContent, filePath)

			callback(event)
			request.options.Progress.IncrementRequests()
		}(data)
	})
	wg.Wait()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	return nil
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, fileContent string, filePath string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(fileContent) {
			hexDump = true
			fileContent = hex.Dump([]byte(fileContent))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, fileContent, cliOptions.NoColor, hexDump)
		gologger.Debug().Msgf("[%s] Dumped file request for %s\n\n%s", requestOptions.TemplateID, filePath, highlightedResponse)
	}
}

// approximateLineFromOperatorMatch returns approximate line count from match
func approximateLineFromOperatorMatch(words []string, contents string) string {
	lines := calculateLineFunc(contents, words)

	var buf strings.Builder

	for i, line := range lines {
		buf.WriteString(strconv.Itoa(line))
		if i != len(lines)-1 {
			buf.WriteString(",")
		}
	}
	return buf.String()
}

func calculateLineFunc(contents string, words []string) []int {
	var lines []int

	for _, word := range words {
		firstIndex := strings.Index(contents, word)
		if firstIndex == -1 {
			return nil
		}
		lineCount := int(0)
		for _, c := range contents[:firstIndex] {
			if c == '\n' {
				lineCount++
			}
		}
		if lineCount > 0 {
			lines = append(lines, lineCount+1)
		}
	}
	return lines
}
