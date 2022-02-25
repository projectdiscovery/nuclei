package file

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
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
	Raw       string
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
			exprLines := make(map[string][]int)
			exprBytes := make(map[string][]int)
			for scanner.Scan() {
				lineContent := scanner.Text()
				n := len(lineContent)

				// update counters
				currentBytes := bytesCount + n
				processedBytes := units.BytesSize(float64(currentBytes))

				gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytes)
				dslMap := request.responseToDSLMap(&fileStatus{
					raw:             lineContent,
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
									Raw:       lineContent,
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
									Raw:       lineContent,
								})
							}
						}
					}
				}

				currentLinesCount := 1 + strings.Count(lineContent, "\n")
				linesCount += currentLinesCount
				wordsCount += strings.Count(lineContent, " ")
				bytesCount = currentBytes

			}

			// build event structure to interface with internal logic
			internalEvent := request.responseToDSLMap(&fileStatus{
				inputFilePath:   input,
				matchedFileName: filePath,
			})
			operatorResult := &operators.Result{}
			for _, fileMatch := range fileMatches {
				operatorResult.Matched = operatorResult.Matched || fileMatch.Match
				operatorResult.Extracted = operatorResult.Extracted || fileMatch.Extract
				switch {
				case fileMatch.Extract:
					if operatorResult.Extracts == nil {
						operatorResult.Extracts = make(map[string][]string)
					}
					if _, ok := operatorResult.Extracts[fileMatch.Expr]; !ok {
						operatorResult.Extracts[fileMatch.Expr] = []string{fileMatch.Data}
					} else {
						operatorResult.Extracts[fileMatch.Expr] = append(operatorResult.Extracts[fileMatch.Expr], fileMatch.Data)
					}
					operatorResult.OutputExtracts = append(operatorResult.OutputExtracts, fileMatch.Data)
					operatorResult.OutputUnique = map[string]struct{}{}
				case fileMatch.Match:
					if operatorResult.Matches == nil {
						operatorResult.Matches = make(map[string][]string)
					}
					if _, ok := operatorResult.Matches[fileMatch.Expr]; !ok {
						operatorResult.Matches[fileMatch.Expr] = []string{fileMatch.Data}
					} else {
						operatorResult.Matches[fileMatch.Expr] = append(operatorResult.Matches[fileMatch.Expr], fileMatch.Data)
					}
				}
				exprLines[fileMatch.Expr] = append(exprLines[fileMatch.Expr], fileMatch.Line)
				exprBytes[fileMatch.Expr] = append(exprBytes[fileMatch.Expr], fileMatch.ByteIndex)
			}

			// build results
			var results []*output.ResultEvent
			for expr, items := range operatorResult.Matches {
				results = append(results, &output.ResultEvent{
					MatcherStatus:    true,
					TemplateID:       types.ToString(internalEvent["template-id"]),
					TemplatePath:     types.ToString(internalEvent["template-path"]),
					Info:             internalEvent["template-info"].(model.Info),
					Type:             types.ToString(internalEvent["type"]),
					Path:             types.ToString(internalEvent["path"]),
					Matched:          types.ToString(internalEvent["path"]),
					Host:             types.ToString(internalEvent["host"]),
					ExtractedResults: items,
					// Response:         types.ToString(wrapped.InternalEvent["raw"]),
					Timestamp:   time.Now(),
					Lines:       exprLines[expr],
					MatcherName: expr,
				})
			}
			for expr, items := range operatorResult.Extracts {
				results = append(results, &output.ResultEvent{
					MatcherStatus:    true,
					TemplateID:       types.ToString(internalEvent["template-id"]),
					TemplatePath:     types.ToString(internalEvent["template-path"]),
					Info:             internalEvent["template-info"].(model.Info),
					Type:             types.ToString(internalEvent["type"]),
					Path:             types.ToString(internalEvent["path"]),
					Matched:          types.ToString(internalEvent["matched"]),
					Host:             types.ToString(internalEvent["host"]),
					ExtractedResults: items,
					Lines:            exprLines[expr],
					ExtractorName:    expr,
					// FileToIndexPosition: exprBytes,
					Timestamp: time.Now(),
				})
			}

			event := &output.InternalWrappedEvent{
				InternalEvent:   internalEvent,
				Results:         results,
				OperatorsResult: operatorResult,
			}
			dumpResponse(event, request.options, fileMatches, filePath)
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

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, filematches []FileMatch, filePath string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		for _, fileMatch := range filematches {
			lineContent := fileMatch.Raw
			hexDump := false
			if responsehighlighter.HasBinaryContent(lineContent) {
				hexDump = true
				lineContent = hex.Dump([]byte(lineContent))
			}
			highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, lineContent, cliOptions.NoColor, hexDump)
			gologger.Debug().Msgf("[%s] Dumped match/extract file snippet for %s at line %d\n\n%s", requestOptions.TemplateID, filePath, fileMatch.Line, highlightedResponse)
		}
	}
}
