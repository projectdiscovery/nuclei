package file

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/docker/go-units"
	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.FileProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
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
			if stat.Size() >= request.maxSize {
				gologger.Verbose().Msgf("Limiting %s processed data to %s bytes: exceeded max size\n", filePath, units.HumanSize(float64(request.maxSize)))
			}
			totalBytes := units.BytesSize(float64(stat.Size()))
			fileReader := io.LimitReader(file, request.maxSize)
			var bytesCount, linesCount, wordsCount int
			scanner := bufio.NewScanner(fileReader)
			buffer := []byte{}
			scanner.Buffer(buffer, int(chunkSize))
			for scanner.Scan() {
				fileContent := scanner.Text()
				n := len(fileContent)

				// update counters
				currentBytes := bytesCount + n
				processedBytes := units.BytesSize(float64(currentBytes))

				gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytes)
				outputEvent := request.toDSLMap(&fileStatus{
					raw:             fileContent,
					inputFilePath:   input,
					matchedFileName: filePath,
					lines:           linesCount,
					words:           wordsCount,
					bytes:           bytesCount,
				})
				for k, v := range previous {
					outputEvent[k] = v
				}

				event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)

				dumpResponse(event, request.options, fileContent, filePath)
				callback(event)

				currentLinesCount := 1 + strings.Count(fileContent, "\n")
				linesCount += currentLinesCount
				wordsCount += strings.Count(fileContent, " ")
				bytesCount = currentBytes
				request.options.Progress.IncrementRequests()
			}
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

func getAllStringSubmatchIndex(content string, word string) []int {
	indexes := []int{}

	start := 0
	for {
		v := strings.Index(content[start:], word)
		if v == -1 {
			break
		}
		indexes = append(indexes, v+start)
		start += len(word) + v
	}
	return indexes
}

func calculateLineFunc(contents string, linesOffset int, words map[string]struct{}) []int {
	var lines []int

	for word := range words {
		matches := getAllStringSubmatchIndex(contents, word)

		for _, index := range matches {
			lineCount := 1 + strings.Count(contents[:index], "\n")
			lines = append(lines, linesOffset+lineCount)
		}
	}
	sort.Ints(lines)
	return lines
}
