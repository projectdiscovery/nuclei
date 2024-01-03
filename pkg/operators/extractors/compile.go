package extractors

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	ExtractedResultsDir = "extracted"
)

// CompileExtractors performs the initial setup operation on an extractor
func (e *Extractor) CompileExtractors() error {
	// Set up the extractor type
	computedType, err := toExtractorTypes(e.GetType().String())
	if err != nil {
		return fmt.Errorf("unknown extractor type specified: %s", e.Type)
	}
	e.extractorType = computedType
	// Compile the regexes
	for _, regex := range e.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		e.regexCompiled = append(e.regexCompiled, compiled)
	}
	for i, kval := range e.KVal {
		e.KVal[i] = strings.ToLower(kval)
	}

	for _, query := range e.JSON {
		query, err := gojq.Parse(query)
		if err != nil {
			return fmt.Errorf("could not parse json: %s", query)
		}
		compiled, err := gojq.Compile(query)
		if err != nil {
			return fmt.Errorf("could not compile json: %s", query)
		}
		e.jsonCompiled = append(e.jsonCompiled, compiled)
	}

	for _, dslExp := range e.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExp, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExp, WrappedError: err}
		}
		e.dslCompiled = append(e.dslCompiled, compiled)
	}

	if e.CaseInsensitive {
		if e.GetType() != KValExtractor {
			return fmt.Errorf("case-insensitive flag is supported only for 'kval' extractors (not '%s')", e.Type)
		}
		for i := range e.KVal {
			e.KVal[i] = strings.ToLower(e.KVal[i])
		}
	}

	// this will only run once regardless of how many times it is called (even if called concurrently)
	e.onceFileInit = sync.OnceFunc(func() {
		// compile output file
		if e.ToFile != "" && !protocolstate.SkipExtractorFileWrite {
			// check if file is outside of cwd
			if strings.Contains(e.ToFile, "/") {
				// when writing to absolute paths or subfolders, lfa is required
				if protocolstate.IsLFAAllowed() {
					file, err := os.OpenFile(e.ToFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						gologger.Error().Msgf("extractor: could not open file %s: %s", e.ToFile, err)
						return
					}
					e.outFile = file
				} else {
					gologger.Error().Msgf("extractor: writing to absolute paths or subfolders(%v) is not allowed, use -lfa to enable", e.ToFile)
					return
				}
			}
			targetFile := e.ToFile
			if !protocolstate.IsLFAAllowed() {
				base := filepath.Base(filepath.Clean(e.ToFile))
				if !fileutil.FolderExists(ExtractedResultsDir) {
					if err := fileutil.CreateFolder(ExtractedResultsDir); err != nil {
						gologger.Error().Msgf("extractor: could not create folder to write extracted results %s: %s", ExtractedResultsDir, err)
						return
					}
				}
				targetFile = filepath.Join(ExtractedResultsDir, base)
			}
			file, err := os.OpenFile(targetFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				gologger.Error().Msgf("extractor: could not open file %s: %s", targetFile, err)
				return
			}
			e.outFile = file

			runtime.SetFinalizer(e.outFile, func(f *os.File) {
				// this will close file when gc finds that this object is not referenced anymore
				if f != nil {
					_ = f.Close()
				}
			})
		}
	})

	return nil
}
