package matchers

import (
	"encoding/hex"
	"fmt"
)

// CompileMatchers performs the initial setup operation on a matcher
func (m *Matcher) CompileMatchers() error {
	if matcherType, ok := MatcherTypes[m.Type]; !ok {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	} else {
		m.matcherType = matcherType
	}

	for _, binary := range m.Binary {
		hexa, _ := hex.DecodeString(binary)
		m.binaryCompiled = append(m.binaryCompiled, string(hexa))
	}

	if m.Negative {
		m.negative = "!"
	}

	// Setup the condition type, if any.
	m.condition = ORCondition
	if m.Condition != "" {
		var ok bool
		m.condition, ok = ConditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	}

	return nil
}
