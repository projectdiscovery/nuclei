package matchers

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/antchfx/xpath"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var commonExpectedFields = []string{"Type", "Condition", "Name", "MatchAll", "Negative", "Internal"}

// Validate perform initial validation on the matcher structure
func (matcher *Matcher) Validate() error {
	// Build a map of YAML‐tag names that are actually set (non-zero) in the matcher.
	matcherMap := make(map[string]interface{})
	val := reflect.ValueOf(*matcher)
	typ := reflect.TypeOf(*matcher)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		// skip internal / unexported or opt-out fields
		yamlTag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if yamlTag == "" || yamlTag == "-" {
			continue
		}
		if val.Field(i).IsZero() {
			continue
		}
		matcherMap[yamlTag] = struct{}{}
	}
	var err error

	var expectedFields []string
	var requiredField string
	var valueCount int
	switch matcher.matcherType {
	case DSLMatcher:
		requiredField, valueCount = "dsl", len(matcher.DSL)
		expectedFields = append(commonExpectedFields, "DSL")
	case StatusMatcher:
		requiredField, valueCount = "status", len(matcher.Status)
		expectedFields = append(commonExpectedFields, "Status", "Part")
	case SizeMatcher:
		requiredField, valueCount = "size", len(matcher.Size)
		expectedFields = append(commonExpectedFields, "Size", "Part")
	case WordsMatcher:
		requiredField, valueCount = "words", len(matcher.Words)
		expectedFields = append(commonExpectedFields, "Words", "Part", "Encoding", "CaseInsensitive")
	case BinaryMatcher:
		requiredField, valueCount = "binary", len(matcher.Binary)
		expectedFields = append(commonExpectedFields, "Binary", "Part", "Encoding", "CaseInsensitive")
	case RegexMatcher:
		requiredField, valueCount = "regex", len(matcher.Regex)
		expectedFields = append(commonExpectedFields, "Regex", "Part", "Encoding", "CaseInsensitive")
	case XPathMatcher:
		requiredField, valueCount = "xpath", len(matcher.XPath)
		expectedFields = append(commonExpectedFields, "XPath", "Part")
	case ErrorMatcher:
		expectedFields = append(commonExpectedFields, "Errors", "CaseInsensitive")
	}

	if err = checkFields(matcher, matcherMap, expectedFields...); err != nil {
		return err
	}

	if requiredField != "" && valueCount == 0 {
		return fmt.Errorf("%s matcher requires at least one %s value", matcher.matcherType, requiredField)
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
