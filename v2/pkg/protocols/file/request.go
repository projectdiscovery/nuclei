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

type FileMatch struct {
	Data      string
	Line      int
	ByteIndex int
	Match     bool
	Extract   bool
	Expr      string
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
			scanner := bufio.NewScanner(fileReader)
			buffer := []byte{}
			scanner.Buffer(buffer, int(chunkSize))

			var fileMatches []FileMatch
			for scanner.Scan() {
				fileContent := scanner.Text()
				n := len(fileContent)

				// update counters
				currentBytes := bytesCount + n
				processedBytes := units.BytesSize(float64(currentBytes))

				gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytes)
				dslMap := request.responseToDSLMap(&fileStatus{
					raw:             fileContent,
					inputFilePath:   input,
					matchedFileName: filePath,
					lines:           linesCount,
					words:           wordsCount,
					bytes:           bytesCount,
				})

				if parts, ok := request.CompiledOperators.Execute(dslMap, request.Match, request.Extract, isResponseDebug); parts != nil && ok {
					if parts.Extracts != nil {
						for expr, extracts := range parts.Extracts {
							for _, extract := range extracts {
								fileMatches = append(fileMatches, FileMatch{
									Data:      extract,
									Extract:   true,
									Line:      linesCount + 1,
									ByteIndex: bytesCount,
									Expr:      expr,
								})
							}
						}
					}
					if parts.Matches != nil {
						for expr, matches := range parts.Matches {
							for _, match := range matches {
								fileMatches = append(fileMatches, FileMatch{
									Data:      match,
									Match:     true,
									Line:      linesCount + 1,
									ByteIndex: bytesCount,
									Expr:      expr,
								})
							}
						}
					}
				}

				currentLinesCount := 1 + strings.Count(fileContent, "\n")
				linesCount += currentLinesCount
				wordsCount += strings.Count(fileContent, " ")
				bytesCount = currentBytes

			}

			// create a new event trying to adapt it for the architecture
			dumpResponse(request.options, fileMatches, filePath)

			// build event to allow the internal logic to hopefully handle it
			event := &output.InternalWrappedEvent{}
			event.Results = append(event.Results, &output.ResultEvent{})
			event := eventcreator.CreateEvent(request, outputEvent, isResponseDebug)
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

func dumpResponse(requestOptions *protocols.ExecuterOptions, filematches []FileMatch, filePath string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		for _, fileMatch := range filematches {
			data := fileMatch.Data
			hexDump := false
			if responsehighlighter.HasBinaryContent(data) {
				hexDump = true
				data = hex.Dump([]byte(data))
			}
			highlightedResponse := responsehighlighter.HighlightAll(data, cliOptions.NoColor, hexDump)
			gologger.Debug().Msgf("[%s] Dumped match/extract file snippet for %s at line %d\n\n%s", requestOptions.TemplateID, filePath, fileMatch.Line, highlightedResponse)
		}
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
