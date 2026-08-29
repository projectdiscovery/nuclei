package extractors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

// CompileExtractors performs the initial setup operation on an extractor
func (e *Extractor) CompileExtractors() error {
	// Set up the extractor type
	computedType, err := toExtractorTypes(e.GetType().String())
	if err != nil {
		return fmt.Errorf("unknown extractor type specified: %s", e.Type)
	}
	e.extractorType = computedType

	if e.extractorType == RegexExtractor && e.RegexGroup < 0 {
		return fmt.Errorf("regex extractor group must be >= 0, got %d", e.RegexGroup)
	}

	// An extractor with no values can never extract anything, so it is always a
	// template authoring mistake. It used to compile and run silently.
	if err := e.checkRequiredValues(); err != nil {
		return err
	}

	// Compile the regexes
	for _, regex := range e.Regex {
		if cached, err := cache.Regex().GetIFPresent(regex); err == nil && cached != nil {
			e.regexCompiled = append(e.regexCompiled, cached)
			continue
		}
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		_ = cache.Regex().Set(regex, compiled)
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
		if cached, err := cache.DSL().GetIFPresent(dslExp); err == nil && cached != nil {
			e.dslCompiled = append(e.dslCompiled, cached)
			continue
		}
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExp, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExp, WrappedError: err}
		}
		_ = cache.DSL().Set(dslExp, compiled)
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

	return nil
}

// checkRequiredValues reports an error when the extractor carries none of the
// values its type extracts with. Such an extractor can never produce a result,
// so it is always a template authoring mistake rather than an intentional no-op.
func (e *Extractor) checkRequiredValues() error {
	var empty bool
	var field string

	switch e.extractorType {
	case RegexExtractor:
		empty, field = len(e.Regex) == 0, "regex"
	case KValExtractor:
		empty, field = len(e.KVal) == 0, "kval"
	case XPathExtractor:
		empty, field = len(e.XPath) == 0, "xpath"
	case JSONExtractor:
		empty, field = len(e.JSON) == 0, "json"
	case DSLExtractor:
		empty, field = len(e.DSL) == 0, "dsl"
	}

	if empty {
		return fmt.Errorf("extractor %s has no %s values specified", e.extractorType, field)
	}
	return nil
}
