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
func (m *Matcher) CompileMatchers() error {
	var ok bool

	// Support hexadecimal encoding for matchers too.
	if m.Encoding == "hex" {
		for i, word := range m.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				m.Words[i] = string(decoded)
			}
		}
	}

	// Set up the matcher type
	computedType, err := toMatcherTypes(m.GetType().String())
	if err != nil {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	}

	m.matcherType = computedType
	// By default, match on body if user hasn't provided any specific items
	if m.Part == "" {
		m.Part = "body"
	}

	// Compile the regexes
	for _, regex := range m.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile and validate binary Values in matcher
	for _, value := range m.Binary {
		if decoded, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("could not hex decode binary: %s", value)
		} else {
			m.binaryDecoded = append(m.binaryDecoded, string(decoded))
		}
	}

	// Compile the dsl expressions
	for _, dslExpression := range m.DSL {
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, dsl.HelperFunctions())
		if err != nil {
			return &DslCompilationError{DslSignature: dslExpression, WrappedError: err}
		}
		m.dslCompiled = append(m.dslCompiled, compiledExpression)
	}

	// Set up the condition type, if any.
	if m.Condition != "" {
		m.condition, ok = ConditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	} else {
		m.condition = ORCondition
	}

	if m.CaseInsensitive {
		if m.GetType() != WordsMatcher {
			return fmt.Errorf("case-insensitive flag is supported only for 'word' matchers (not '%s')", m.Type)
		}
		for i := range m.Words {
			m.Words[i] = strings.ToLower(m.Words[i])
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
