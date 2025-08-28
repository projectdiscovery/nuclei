package extractors

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

var (
	extractorRegexCache        sync.Map // map[string]*regexp.Regexp
	extractorDslCache          sync.Map // map[string]*govaluate.EvaluableExpression
	extractorMaxRegexCacheSize = 4096
	extractorMaxDslCacheSize   = 4096
	extractorRegexCacheSize    atomic.Int64
	extractorDslCacheSize      atomic.Int64
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
		if cached, ok := extractorRegexCache.Load(regex); ok {
			e.regexCompiled = append(e.regexCompiled, cached.(*regexp.Regexp))
			continue
		}
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		if extractorRegexCacheSize.Load() < int64(extractorMaxRegexCacheSize) {
			if prev, loaded := extractorRegexCache.LoadOrStore(regex, compiled); loaded {
				e.regexCompiled = append(e.regexCompiled, prev.(*regexp.Regexp))
			} else {
				e.regexCompiled = append(e.regexCompiled, compiled)
				extractorRegexCacheSize.Add(1)
			}
		} else {
			e.regexCompiled = append(e.regexCompiled, compiled)
		}
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
		if cached, ok := extractorDslCache.Load(dslExp); ok {
			e.dslCompiled = append(e.dslCompiled, cached.(*govaluate.EvaluableExpression))
			continue
		}
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExp, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExp, WrappedError: err}
		}
		if extractorDslCacheSize.Load() < int64(extractorMaxDslCacheSize) {
			if prev, loaded := extractorDslCache.LoadOrStore(dslExp, compiled); loaded {
				e.dslCompiled = append(e.dslCompiled, prev.(*govaluate.EvaluableExpression))
			} else {
				e.dslCompiled = append(e.dslCompiled, compiled)
				extractorDslCacheSize.Add(1)
			}
		} else {
			e.dslCompiled = append(e.dslCompiled, compiled)
		}
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
