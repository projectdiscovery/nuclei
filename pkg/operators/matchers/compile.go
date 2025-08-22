package matchers

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/Knetic/govaluate"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

var (
	regexCache        sync.Map // map[string]*regexp.Regexp
	dslCache          sync.Map // map[string]*govaluate.EvaluableExpression
	maxRegexCacheSize = 4096
	maxDslCacheSize   = 4096
)

func cacheLen(m *sync.Map) int {
	n := 0
	m.Range(func(key, value any) bool { n++; return true })
	return n
}

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

	// Compile the regexes (with cache)
	for _, regex := range matcher.Regex {
		if cached, ok := regexCache.Load(regex); ok {
			matcher.regexCompiled = append(matcher.regexCompiled, cached.(*regexp.Regexp))
			continue
		}
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		if cacheLen(&regexCache) < maxRegexCacheSize {
			if prev, loaded := regexCache.LoadOrStore(regex, compiled); loaded {
				matcher.regexCompiled = append(matcher.regexCompiled, prev.(*regexp.Regexp))
			} else {
				matcher.regexCompiled = append(matcher.regexCompiled, compiled)
			}
		} else {
			matcher.regexCompiled = append(matcher.regexCompiled, compiled)
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

	// Compile the dsl expressions (with cache)
	for _, dslExpression := range matcher.DSL {
		if cached, ok := dslCache.Load(dslExpression); ok {
			matcher.dslCompiled = append(matcher.dslCompiled, cached.(*govaluate.EvaluableExpression))
			continue
		}
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, dsl.HelperFunctions)
		if err != nil {
			return &dsl.CompilationError{DslSignature: dslExpression, WrappedError: err}
		}
		if cacheLen(&dslCache) < maxDslCacheSize {
			if prev, loaded := dslCache.LoadOrStore(dslExpression, compiledExpression); loaded {
				matcher.dslCompiled = append(matcher.dslCompiled, prev.(*govaluate.EvaluableExpression))
			} else {
				matcher.dslCompiled = append(matcher.dslCompiled, compiledExpression)
			}
		} else {
			matcher.dslCompiled = append(matcher.dslCompiled, compiledExpression)
		}
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

// GetType returns the condition type of the matcher
// todo: the field should be exposed natively
func (matcher *Matcher) GetCondition() ConditionType {
	return matcher.condition
}
