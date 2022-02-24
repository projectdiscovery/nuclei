package file

import (
	"bufio"
	"encoding/hex"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/docker/go-units"
	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/sliceutil"
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
			isResponseDebug := request.options.Options.Debug || request.options.Options.DebugResponse
			var result *operators.Result
			scanner := bufio.NewScanner(fileReader)
			buffer := []byte{}
			scanner.Buffer(buffer, int(chunkSize))
			outputEvent := request.responseToDSLMap(&fileStatus{
				inputFilePath:   input,
				matchedFileName: filePath,
			})
			for k, v := range previous {
				outputEvent[k] = v
			}

			var allMatches []*output.InternalEvent
			for scanner.Scan() {
				fileContent := scanner.Text()
				n := len(fileContent)

				// update counters
				currentBytes := bytesCount + n
				processedBytes := units.BytesSize(float64(currentBytes))

				gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytes)
				chunkOutputEvent := request.responseToDSLMap(&fileStatus{
					raw:             fileContent,
					inputFilePath:   input,
					matchedFileName: filePath,
					lines:           linesCount,
					words:           wordsCount,
					bytes:           bytesCount,
				})
				for k, v := range previous {
					chunkOutputEvent[k] = v
				}

				chunkEvent := eventcreator.CreateEvent(request, chunkOutputEvent, isResponseDebug)
				if chunkEvent.OperatorsResult != nil {
					chunkOutputEvent["results"] = *chunkEvent.OperatorsResult
					allMatches = append(allMatches, &chunkOutputEvent)
					if result == nil {
						result = chunkEvent.OperatorsResult
					} else {
						result.Merge(chunkEvent.OperatorsResult)
					}
					dumpResponse(chunkEvent, request.options, filePath, linesCount)
				}

				currentLinesCount := 1 + strings.Count(fileContent, "\n")
				linesCount += currentLinesCount
				wordsCount += strings.Count(fileContent, " ")
				bytesCount = currentBytes

			}
			outputEvent["all_matches"] = allMatches
			log.Printf("%#v\n", result)
			callback(eventcreator.CreateEventWithResults(request, outputEvent, isResponseDebug, result))
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

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, filePath string, line int) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		fileContent := event.InternalEvent["raw"].(string)
		hexDump := false
		if responsehighlighter.HasBinaryContent(fileContent) {
			hexDump = true
			fileContent = hex.Dump([]byte(fileContent))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, fileContent, cliOptions.NoColor, hexDump)
		gologger.Debug().Msgf("[%s] Dumped match/extract file snippet for %s at line %d\n\n%s", requestOptions.TemplateID, filePath, line+1, highlightedResponse)
	}
}

func calculateLineFunc(allMatches []*output.InternalEvent, words map[string]struct{}) []int {
	var lines []int
	for word := range words {
		for _, match := range allMatches {
			matchPt := *match
			opResult := matchPt["results"].(operators.Result)
			if opResult.Matched {
				for _, matchedItems := range opResult.Matches {
					for _, matchedItem := range matchedItems {
						if word == matchedItem {
							lines = append(lines, matchPt["lines"].(int)+1)
						}
					}
				}
			}
			for _, v := range opResult.OutputExtracts {
				if word == v {
					lines = append(lines, matchPt["lines"].(int)+1)
				}
			}
		}
		_ = word
	}
	lines = sliceutil.DedupeInt(lines)
	sort.Ints(lines)
	return lines
}

func calculateFileIndexFunc(allMatches []*output.InternalEvent, extraction string) int {
	for _, match := range allMatches {
		matchPt := *match
		opResult := matchPt["results"].(operators.Result)
		for _, extracts := range opResult.Extracts {
			for _, extract := range extracts {
				if extraction == extract {
					return matchPt["bytes"].(int)
				}
			}
		}
	}
	return -1
}
