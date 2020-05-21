package matchers

import (
	"fmt"
	"regexp"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/pkg/generators"
)

// CompileMatchers performs the initial setup operation on a matcher
func (m *Matcher) CompileMatchers() error {
	var ok bool

	// Setup the matcher type
	m.matcherType, ok = MatcherTypes[m.Type]
	if !ok {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	}

	// Compile the regexes
	for _, regex := range m.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}

		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile the dsl expressions
	for _, dsl := range m.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dsl, generators.HelperFunctions())
		if err != nil {
			return fmt.Errorf("could not compile dsl: %s", dsl)
		}

		m.dslCompiled = append(m.dslCompiled, compiled)
	}

	// Setup the condition type, if any.
	if m.Condition != "" {
		m.condition, ok = ConditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	} else {
		m.condition = ORCondition
	}

	// Setup the part of the request to match, if any.
	if m.Part != "" {
		m.part, ok = PartTypes[m.Part]
		if !ok {
			return fmt.Errorf("unknown matcher part specified: %s", m.Part)
		}
	} else {
		m.part = BodyPart
	}
	return nil
}
