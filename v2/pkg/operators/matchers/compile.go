package matchers

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
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
	// By default, match on body if user hasn't provided any specific items
	if matcher.Part == "" {
		matcher.Part = "body"
	}

	// Compile the regexes
	for _, regex := range matcher.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		matcher.regexCompiled = append(matcher.regexCompiled, compiled)
	}

	// Compile and validate binary Values in matcher
	for _, value := range matcher.Binary {
		if decoded, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("could not hex decode binary: %s", value)
		} else {
			matcher.binaryDecoded = append(matcher.binaryDecoded, string(decoded))
		}
	}

	// Compile the dsl expressions
	for _, dslExpression := range matcher.DSL {
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, dsl.HelperFunctions())
		if err != nil {
			return &DslCompilationError{DslSignature: dslExpression, WrappedError: err}
		}
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

type DslCompilationError struct {
	DslSignature string
	WrappedError error
}

func (e *DslCompilationError) Error() string {
	return fmt.Sprintf("could not compile DSL expression: %s. %v", e.DslSignature, e.WrappedError)
}

func (e *DslCompilationError) Unwrap() error {
	return e.WrappedError
}
