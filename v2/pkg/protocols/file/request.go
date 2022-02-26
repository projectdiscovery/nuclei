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

			fileReader := io.LimitReader(file, request.maxSize)
			fileMatches := request.collectMatches(fileReader, input, filePath, units.BytesSize(float64(stat.Size())))

			// build event structure to interface with internal logic
			event := request.buildEvent(input, filePath, fileMatches)
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

func (request *Request) collectMatches(reader io.Reader, input, filePath, totalBytes string) []FileMatch {
	var bytesCount, linesCount, wordsCount int
	isResponseDebug := request.options.Options.Debug || request.options.Options.DebugResponse
	scanner := bufio.NewScanner(reader)
	buffer := []byte{}
	scanner.Buffer(buffer, int(chunkSize))

	var fileMatches []FileMatch
	for scanner.Scan() {
		lineContent := scanner.Text()
		n := len(lineContent)

		// update counters
		currentBytes := bytesCount + n
		processedBytes := units.BytesSize(float64(currentBytes))

		gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytes)
		dslMap := request.responseToDSLMap(lineContent, input, filePath)
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
	return fileMatches
}

func (request *Request) buildEvent(input, filePath string, fileMatches []FileMatch) *output.InternalWrappedEvent {
	exprLines := make(map[string][]int)
	exprBytes := make(map[string][]int)
	internalEvent := request.responseToDSLMap("", input, filePath)
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
			if operatorResult.OutputUnique == nil {
				operatorResult.OutputUnique = make(map[string]struct{})
			}
			operatorResult.OutputUnique[fileMatch.Data] = struct{}{}
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
			Matched:          types.ToString(internalEvent["matched"]),
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

	return &output.InternalWrappedEvent{
		InternalEvent:   internalEvent,
		Results:         results,
		OperatorsResult: operatorResult,
	}
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
