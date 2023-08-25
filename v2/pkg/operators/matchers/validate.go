package matchers

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/antchfx/xpath"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"gopkg.in/yaml.v3"
)

var commonExpectedFields = []string{"Type", "Condition", "Name", "MatchAll", "Negative"}

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
		expectedFields = append(commonExpectedFields, "DSL")
	case StatusMatcher:
		expectedFields = append(commonExpectedFields, "Status", "Part")
	case SizeMatcher:
		expectedFields = append(commonExpectedFields, "Size", "Part")
	case WordsMatcher:
		expectedFields = append(commonExpectedFields, "Words", "Part", "Encoding", "CaseInsensitive")
	case BinaryMatcher:
		expectedFields = append(commonExpectedFields, "Binary", "Part", "Encoding", "CaseInsensitive")
	case RegexMatcher:
		expectedFields = append(commonExpectedFields, "Regex", "Part", "Encoding", "CaseInsensitive")
	case XPathMatcher:
		expectedFields = append(commonExpectedFields, "XPath", "Part")
	}

	if err = checkFields(matcher, matcherMap, expectedFields...); err != nil {
		return err
	}

	// validate the XPath query
	if matcher.matcherType == XPathMatcher {
		for _, query := range matcher.XPath {
			if _, err = xpath.Compile(query); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkFields(m *Matcher, matcherMap map[string]interface{}, expectedFields ...string) error {
	var foundUnexpectedFields []string
	for marshaledFieldName := range matcherMap {
		// revert back the marshaled name to the original field
		structFieldName, err := getFieldNameFromYamlTag(marshaledFieldName, *m)
		if err != nil {
			return err
		}
		if !sliceutil.Contains(expectedFields, structFieldName) {
			foundUnexpectedFields = append(foundUnexpectedFields, structFieldName)
		}
	}
	if len(foundUnexpectedFields) > 0 {
		return fmt.Errorf("matcher %s has unexpected fields: %s", m.matcherType, strings.Join(foundUnexpectedFields, ","))
	}
	return nil
}

func getFieldNameFromYamlTag(tagName string, object interface{}) (string, error) {
	reflectType := reflect.TypeOf(object)
	if reflectType.Kind() != reflect.Struct {
		return "", errors.New("the object must be a struct")
	}
	for idx := 0; idx < reflectType.NumField(); idx++ {
		field := reflectType.Field(idx)
		tagParts := strings.Split(field.Tag.Get("yaml"), ",")
		if len(tagParts) > 0 && tagParts[0] == tagName {
			return field.Name, nil
		}
	}
	return "", fmt.Errorf("field %s not found", tagName)
}
