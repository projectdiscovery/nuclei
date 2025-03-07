package file

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/go-units"
	"github.com/mholt/archives"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
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

var errEmptyResult = errors.New("Empty result")

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	wg, err := syncutil.New(syncutil.WithSize(request.options.Options.BulkSize))
	if err != nil {
		return err
	}
	if input.MetaInput.Input == "" {
		return errors.New("input cannot be empty file or folder expected")
	}
	err = request.getInputPaths(input.MetaInput.Input, func(filePath string) {
		wg.Add()
		func(filePath string) {
			defer wg.Done()
			fi, err := os.Open(filePath)
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				return
			}
			defer fi.Close()
			format, stream, _ := archives.Identify(input.Context(), filePath, fi)
			switch {
			case format != nil:
				switch archiveInstance := format.(type) {
				case archives.Extractor:
					err := archiveInstance.Extract(input.Context(), stream, func(ctx context.Context, file archives.FileInfo) error {
						if !request.validatePath("/", file.Name(), true) {
							return nil
						}
						// every new file in the compressed multi-file archive counts 1
						request.options.Progress.AddToTotal(1)
						archiveFileName := filepath.Join(filePath, file.Name())
						reader, err := file.Open()
						if err != nil {
							gologger.Error().Msgf("%s\n", err)
							return err
						}
						defer reader.Close()
						event, fileMatches, err := request.processReader(reader, archiveFileName, input, file.Size(), previous)
						if err != nil {
							if errors.Is(err, errEmptyResult) {
								// no matches but one file elaborated
								request.options.Progress.IncrementRequests()
								return nil
							}
							gologger.Error().Msgf("%s\n", err)
							// error while elaborating the file
							request.options.Progress.IncrementFailedRequestsBy(1)
							return err
						}
						dumpResponse(event, request.options, fileMatches, filePath)
						callback(event)
						// file elaborated and matched
						request.options.Progress.IncrementRequests()
						return nil
					})
					if err != nil {
						gologger.Error().Msgf("%s\n", err)
						return
					}
				case archives.Decompressor:
					// compressed archive - contains only one file => increments the counter by 1
					request.options.Progress.AddToTotal(1)
					reader, err := archiveInstance.OpenReader(stream)
					if err != nil {
						gologger.Error().Msgf("%s\n", err)
						// error while elaborating the file
						request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					fileStat, _ := fi.Stat()
					tmpFileOut, err := os.CreateTemp("", "")
					if err != nil {
						gologger.Error().Msgf("%s\n", err)
						// error while elaborating the file
						request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					defer tmpFileOut.Close()
					defer os.RemoveAll(tmpFileOut.Name())
					_, err = io.Copy(tmpFileOut, reader)
					if err != nil {
						gologger.Error().Msgf("%s\n", err)
						// error while elaborating the file
						request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					_ = tmpFileOut.Sync()
					// rewind the file
					_, _ = tmpFileOut.Seek(0, 0)
					event, fileMatches, err := request.processReader(tmpFileOut, filePath, input, fileStat.Size(), previous)
					if err != nil {
						if errors.Is(err, errEmptyResult) {
							// no matches but one file elaborated
							request.options.Progress.IncrementRequests()
							return
						}
						gologger.Error().Msgf("%s\n", err)
						// error while elaborating the file
						request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					dumpResponse(event, request.options, fileMatches, filePath)
					callback(event)
					// file elaborated and matched
					request.options.Progress.IncrementRequests()
				}
			default:
				// normal file - increments the counter by 1
				request.options.Progress.AddToTotal(1)
				event, fileMatches, err := request.processFile(filePath, input, previous)
				if err != nil {
					if errors.Is(err, errEmptyResult) {
						// no matches but one file elaborated
						request.options.Progress.IncrementRequests()
						return
					}
					gologger.Error().Msgf("%s\n", err)
					// error while elaborating the file
					request.options.Progress.IncrementFailedRequestsBy(1)
					return
				}
				dumpResponse(event, request.options, fileMatches, filePath)
				callback(event)
				// file elaborated and matched
				request.options.Progress.IncrementRequests()
			}
		}(filePath)
	})

	wg.Wait()
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not send file request")
	}
	return nil
}

func (request *Request) processFile(filePath string, input *contextargs.Context, previousInternalEvent output.InternalEvent) (*output.InternalWrappedEvent, []FileMatch, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, errors.Errorf("Could not open file path %s: %s\n", filePath, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, nil, errors.Errorf("Could not stat file path %s: %s\n", filePath, err)
	}
	if stat.Size() >= request.maxSize {
		maxSizeString := units.HumanSize(float64(request.maxSize))
		gologger.Verbose().Msgf("Limiting %s processed data to %s bytes: exceeded max size\n", filePath, maxSizeString)
	}

	return request.processReader(file, filePath, input, stat.Size(), previousInternalEvent)
}

func (request *Request) processReader(reader io.Reader, filePath string, input *contextargs.Context, totalBytes int64, previousInternalEvent output.InternalEvent) (*output.InternalWrappedEvent, []FileMatch, error) {
	fileReader := io.LimitReader(reader, request.maxSize)
	fileMatches, opResult := request.findMatchesWithReader(fileReader, input, filePath, totalBytes, previousInternalEvent)
	if opResult == nil && len(fileMatches) == 0 {
		return nil, nil, errEmptyResult
	}

	// build event structure to interface with internal logic
	return request.buildEvent(input.MetaInput.Input, filePath, fileMatches, opResult, previousInternalEvent), fileMatches, nil
}

func (request *Request) findMatchesWithReader(reader io.Reader, input *contextargs.Context, filePath string, totalBytes int64, previous output.InternalEvent) ([]FileMatch, *operators.Result) {
	var bytesCount, linesCount, wordsCount int
	isResponseDebug := request.options.Options.Debug || request.options.Options.DebugResponse
	totalBytesString := units.BytesSize(float64(totalBytes))

	// we are forced to check if the whole file needs to be elaborated
	// - matchers-condition option set to AND
	hasAndCondition := request.CompiledOperators.GetMatchersCondition() == matchers.ANDCondition
	// - any matcher has AND condition
	for _, matcher := range request.CompiledOperators.Matchers {
		if hasAndCondition {
			break
		}
		if matcher.GetCondition() == matchers.ANDCondition {
			hasAndCondition = true
		}
	}

	scanner := bufio.NewScanner(reader)
	buffer := []byte{}
	if hasAndCondition {
		scanner.Buffer(buffer, int(defaultMaxReadSize))
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			defaultMaxReadSizeInt := int(defaultMaxReadSize)
			if len(data) > defaultMaxReadSizeInt {
				return defaultMaxReadSizeInt, data[0:defaultMaxReadSizeInt], nil
			}
			if !atEOF {
				return 0, nil, nil
			}
			return len(data), data, bufio.ErrFinalToken
		})
	} else {
		scanner.Buffer(buffer, int(chunkSize))
	}

	var fileMatches []FileMatch
	var opResult *operators.Result
	for scanner.Scan() {
		lineContent := scanner.Text()
		n := len(lineContent)

		// update counters
		currentBytes := bytesCount + n
		processedBytes := units.BytesSize(float64(currentBytes))

		gologger.Verbose().Msgf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytesString)
		dslMap := request.responseToDSLMap(lineContent, input.MetaInput.Input, filePath)
		for k, v := range previous {
			dslMap[k] = v
		}
		// add vars to template context
		request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, dslMap)
		// add template context variables to DSL map
		if request.options.HasTemplateCtx(input.MetaInput) {
			dslMap = generators.MergeMaps(dslMap, request.options.GetTemplateCtx(input.MetaInput).GetAll())
		}
		discardEvent := eventcreator.CreateEvent(request, dslMap, isResponseDebug)
		newOpResult := discardEvent.OperatorsResult
		if newOpResult != nil {
			if opResult == nil {
				opResult = newOpResult
			} else {
				opResult.Merge(newOpResult)
			}
			if newOpResult.Matched || newOpResult.Extracted {
				if newOpResult.Extracts != nil {
					for expr, extracts := range newOpResult.Extracts {
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
				if newOpResult.Matches != nil {
					for expr, matches := range newOpResult.Matches {
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
				for _, outputExtract := range newOpResult.OutputExtracts {
					fileMatches = append(fileMatches, FileMatch{
						Data:      outputExtract,
						Match:     true,
						Line:      linesCount + 1,
						ByteIndex: bytesCount,
						Expr:      outputExtract,
						Raw:       lineContent,
					})
				}
			}
		}

		currentLinesCount := 1 + strings.Count(lineContent, "\n")
		linesCount += currentLinesCount
		wordsCount += strings.Count(lineContent, " ")
		bytesCount = currentBytes
	}
	return fileMatches, opResult
}

func (request *Request) buildEvent(input, filePath string, fileMatches []FileMatch, operatorResult *operators.Result, previous output.InternalEvent) *output.InternalWrappedEvent {
	exprLines := make(map[string][]int)
	exprBytes := make(map[string][]int)
	internalEvent := request.responseToDSLMap("", input, filePath)
	for k, v := range previous {
		internalEvent[k] = v
	}
	for _, fileMatch := range fileMatches {
		exprLines[fileMatch.Expr] = append(exprLines[fileMatch.Expr], fileMatch.Line)
		exprBytes[fileMatch.Expr] = append(exprBytes[fileMatch.Expr], fileMatch.ByteIndex)
	}
	event := eventcreator.CreateEventWithOperatorResults(request, internalEvent, operatorResult)
	// Annotate with line numbers if asked by the user
	if request.options.Options.ShowMatchLine {
		for _, result := range event.Results {
			switch {
			case result.MatcherName != "":
				result.Lines = exprLines[result.MatcherName]
			case result.ExtractorName != "":
				result.Lines = exprLines[result.ExtractorName]
			default:
				for _, extractedResult := range result.ExtractedResults {
					result.Lines = append(result.Lines, exprLines[extractedResult]...)
				}
			}
			result.Lines = sliceutil.Dedupe(result.Lines)
		}
	}
	return event
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecutorOptions, filematches []FileMatch, filePath string) {
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
