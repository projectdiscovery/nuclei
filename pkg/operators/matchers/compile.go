package matchers

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

// CompileMatchers performs the initial setup operation on a matcher
func (matcher *Matcher) CompileMatchers() error {
	var ok bool

	// Support hexadecimal encoding for matchers too.
	if matcher.Encoding == "hex" {
		for i, word := range matcher.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				matcher.Words[i] = string(decoded)
			}
		}
	}

	// Set up the matcher type
	computedType, err := toMatcherTypes(matcher.GetType().String())
	if err != nil {
		return fmt.Errorf("unknown matcher type specified: %s", matcher.Type)
	}

	matcher.matcherType = computedType

	// Validate the matcher structure
	if err := matcher.Validate(); err != nil {
		return err
	}

	// By default, match on body if user hasn't provided any specific items
	if matcher.Part == "" && matcher.GetType() != DSLMatcher {
		matcher.Part = "body"
	}

	// Compile the regexes (with shared cache)
	for _, regex := range matcher.Regex {
		compiled, err := compileRegex(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		matcher.regexCompiled = append(matcher.regexCompiled, compiled)

		if matcher.Offset != nil {
			offsetCompiled, err := compileOffsetRegex(regex, *matcher.Offset)
			if err != nil {
				return fmt.Errorf("could not compile regex: %s", regex)
			}
			matcher.offsetRegexCompiled = append(matcher.offsetRegexCompiled, offsetCompiled)
		}
	}

	// Compile and validate binary Values in matcher
	for _, value := range matcher.Binary {
		if decoded, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("could not hex decode binary: %s", value)
		} else {
			matcher.binaryDecoded = append(matcher.binaryDecoded, string(decoded))
		}
	}

	// Compile the dsl expressions (with shared cache)
	for _, dslExpression := range matcher.DSL {
		if cached, err := cache.DSL().GetIFPresent(dslExpression); err == nil && cached != nil {
			matcher.dslCompiled = append(matcher.dslCompiled, cached)
			continue
		}
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExpression, WrappedError: err}
		}
		_ = cache.DSL().Set(dslExpression, compiledExpression)
		matcher.dslCompiled = append(matcher.dslCompiled, compiledExpression)
	}

	// Set up the condition type, if any.
	if matcher.Condition != "" {
		matcher.condition, ok = ConditionTypes[matcher.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", matcher.Condition)
		}
	} else {
		matcher.condition = ORCondition
	}

	if matcher.CaseInsensitive {
		if matcher.GetType() != WordsMatcher {
			return fmt.Errorf("case-insensitive flag is supported only for 'word' matchers (not '%s')", matcher.Type)
		}
		for i := range matcher.Words {
			matcher.Words[i] = strings.ToLower(matcher.Words[i])
		}
	}
	return nil
}

// compileRegex compiles pattern through the shared regex cache
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if cached, err := cache.Regex().GetIFPresent(pattern); err == nil && cached != nil {
		return cached, nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	_ = cache.Regex().Set(pattern, compiled)
	return compiled, nil
}

// compileOffsetRegex compiles the variant of pattern used when a matcher is
// pinned to a byte offset. The pattern is anchored so a single match attempt
// answers whether it matches at the requested position, and for offsets past
// the start of the corpus it also consumes the rune preceding the offset. That
// leading rune is matched against the real bytes of the corpus, so ^, \A, \b
// and \B keep seeing the context they would see during a normal scan.
func compileOffsetRegex(pattern string, offset int) (*regexp.Regexp, error) {
	anchored := `\A(?:` + pattern + `)`
	if offset > 0 {
		anchored = `\A(?s:.)(?:` + pattern + `)`
	}
	return compileRegex(anchored)
}

// GetType returns the condition type of the matcher
// todo: the field should be exposed natively
func (matcher *Matcher) GetCondition() ConditionType {
	return matcher.condition
}
