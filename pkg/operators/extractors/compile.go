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

	// Compile the regexes
	for _, regex := range e.Regex {
		if cached, err := cache.Regex().GetIFPresent(regex); err == nil && cached != nil {
			if err := validateRegexGroup(e, cached, regex); err != nil {
				return err
			}
			e.regexCompiled = append(e.regexCompiled, cached)
			continue
		}
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		if err := validateRegexGroup(e, compiled, regex); err != nil {
			return err
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

// validateRegexGroup rejects a group index the pattern cannot produce.
//
// ExtractRegex skips any submatch where `len(match) < RegexGroup+1`, and
// FindAllStringSubmatch returns exactly NumSubexp()+1 entries, so a group
// beyond that count can never match anything. Without this the template
// compiles, runs, and silently extracts nothing — the failure mode is an
// empty result rather than an error, which is indistinguishable from "the
// pattern didn't match the target".
func validateRegexGroup(e *Extractor, compiled *regexp.Regexp, pattern string) error {
	if e.extractorType != RegexExtractor || e.RegexGroup == 0 {
		return nil
	}
	if groups := compiled.NumSubexp(); e.RegexGroup > groups {
		return fmt.Errorf(
			"regex extractor group %d is out of range for pattern %q, which has %d capture group(s)",
			e.RegexGroup, pattern, groups,
		)
	}
	return nil
}
