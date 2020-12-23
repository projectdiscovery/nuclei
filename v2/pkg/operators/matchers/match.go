package matchers

import (
	"encoding/hex"
	"strings"
)

// Match matches a generic data response again a given matcher
func (m *Matcher) Match(data map[string]interface{}) bool {
	part, ok := data[m.Part]
	if !ok {
		return false
	}
	partString := part.(string)

	switch m.matcherType {
	case StatusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false
		}
		return m.isNegative(m.matchStatusCode(statusCode.(int)))
	case SizeMatcher:
		return m.isNegative(m.matchSizeCode(len(partString)))
	case WordsMatcher:
		return m.isNegative(m.matchWords(partString))
	case RegexMatcher:
		return m.isNegative(m.matchRegex(partString))
	case BinaryMatcher:
		return m.isNegative(m.matchBinary(partString))
	case DSLMatcher:
		return m.isNegative(m.matchDSL(data))
	}
	return false
}

// matchStatusCode matches a status code check against an HTTP Response
func (m *Matcher) matchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range m.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchStatusCode matches a size check against an HTTP Response
func (m *Matcher) matchSizeCode(length int) bool {
	// Iterate over all the sizes accepted as valid
	//
	// Sizes codes don't support AND conditions.
	for _, size := range m.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchWords(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, word := range m.Words {
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Words)-1 == i {
			return true
		}
	}
	return false
}

// matchRegex matches a regex check against an HTTP Response/Headers.
func (m *Matcher) matchRegex(corpus string) bool {
	// Iterate over all the regexes accepted as valid
	for i, regex := range m.regexCompiled {
		// Continue if the regex doesn't match
		if !regex.MatchString(corpus) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the regex, return with true
		if len(m.regexCompiled)-1 == i {
			return true
		}
	}
	return false
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchBinary(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, binary := range m.Binary {
		// Continue if the word doesn't match
		hexa, _ := hex.DecodeString(binary)
		if !strings.Contains(corpus, string(hexa)) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Binary)-1 == i {
			return true
		}
	}
	return false
}

// matchDSL matches on a generic map result
func (m *Matcher) matchDSL(mp map[string]interface{}) bool {
	// Iterate over all the expressions accepted as valid
	for i, expression := range m.dslCompiled {
		result, err := expression.Evaluate(mp)
		if err != nil {
			continue
		}

		var bResult bool
		bResult, ok := result.(bool)

		// Continue if the regex doesn't match
		if !ok || !bResult {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the dsl, return with true
		if len(m.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}
