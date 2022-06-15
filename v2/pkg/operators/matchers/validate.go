package matchers

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

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

	var unexpectedFields []string
	switch matcher.matcherType {
	case DSLMatcher:
		unexpectedFields = []string{"status", "regex", "words", "size", "binary", "part"}
	case StatusMatcher:
		unexpectedFields = []string{"dsl", "regex", "words", "size", "binary"}
	case SizeMatcher:
		unexpectedFields = []string{"dsl", "regex", "words", "status", "binary"}
	case WordsMatcher:
		unexpectedFields = []string{"dsl", "regex", "size", "status", "binary"}
	case BinaryMatcher:
		unexpectedFields = []string{"dsl", "regex", "size", "status", "words"}
	case RegexMatcher:
		unexpectedFields = []string{"dsl", "binary", "size", "status", "words"}
	}
	return checkUnexpectedFields(matcher, matcherMap, unexpectedFields...)
}

func checkUnexpectedFields(m *Matcher, matcherMap map[string]interface{}, unexpectedFields ...string) error {
	var foundUnexpectedFields []string
	for _, name := range unexpectedFields {
		if _, ok := matcherMap[name]; ok {
			foundUnexpectedFields = append(foundUnexpectedFields, name)
		}
	}
	if len(foundUnexpectedFields) > 0 {
		return fmt.Errorf("matcher %s has unexpected fields: %s", m.matcherType, strings.Join(foundUnexpectedFields, ","))
	}
	return nil
}
