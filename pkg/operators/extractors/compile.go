package extractors

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	extractedResultsDir = "extracted"
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

	// compile output file
	if e.ToFile != "" {
		// check if file is outside of cwd
		if strings.Contains(e.ToFile, "/") {
			// when writing to absolute paths or subfolders, lfa is required
			if protocolstate.IsLFAAllowed() {
				file, err := os.OpenFile(e.ToFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					return fmt.Errorf("could not open file %s: %s", e.ToFile, err)
				}
				e.outFile = file
			} else {
				return fmt.Errorf("extractor: writing to absolute paths or subfolders is not allowed, use -lfa to enable")
			}
		}
		base := filepath.Base(filepath.Clean(e.ToFile))
		if !fileutil.FolderExists(extractedResultsDir) {
			if err := fileutil.CreateFolder(extractedResultsDir); err != nil {
				return fmt.Errorf("could not create folder to write extracted results %s: %s", extractedResultsDir, err)
			}
		}
		targetFile := filepath.Join(extractedResultsDir, base)
		file, err := os.OpenFile(targetFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("could not open file %s: %s", e.ToFile, err)
		}
		e.outFile = file
	}
	return nil
}
