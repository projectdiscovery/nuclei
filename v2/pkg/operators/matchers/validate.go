package matchers

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/sliceutil"
	"gopkg.in/yaml.v3"
)

var commonExpectedFields = []string{"type", "condition", "name", "match-all", "negative"}

// Validate perform initial validation on the matcher structure
func (matcher *Matcher) Validate() error {
	// uses yaml marshaling to convert the struct to map[string]interface to have same field names
	matcherMap := make(map[string]interface{})
	marshaledMatcher, err := yaml.Marshal(matcher)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(marshaledMatcher, &matcherMap); err != nil {
		return err
	}

	var expectedFields []string
	switch matcher.matcherType {
	case DSLMatcher:
		expectedFields = append(commonExpectedFields, "dsl")
	case StatusMatcher:
		expectedFields = append(commonExpectedFields, "status", "part")
	case SizeMatcher:
		expectedFields = append(commonExpectedFields, "size", "part")
	case WordsMatcher:
		expectedFields = append(commonExpectedFields, "words", "part", "encoding", "case-insensitive")
	case BinaryMatcher:
		expectedFields = append(commonExpectedFields, "binary", "part", "encoding", "case-insensitive")
	case RegexMatcher:
		expectedFields = append(commonExpectedFields, "regex", "part", "encoding", "case-insensitive")
	}
	return checkFields(matcher, matcherMap, expectedFields...)
}

func checkFields(m *Matcher, matcherMap map[string]interface{}, expectedFields ...string) error {
	var foundUnexpectedFields []string
	for name := range matcherMap {
		if !sliceutil.Contains(expectedFields, name) {
			foundUnexpectedFields = append(foundUnexpectedFields, name)
		}
	}
	if len(foundUnexpectedFields) > 0 {
		return fmt.Errorf("matcher %s has unexpected fields: %s", m.matcherType, strings.Join(foundUnexpectedFields, ","))
	}
	return nil
}
