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

	// An operator with no values can never match, so it is always an authoring
	// mistake — but it used to compile and run silently, producing zero results
	// with no diagnostic. Reject it here so `-validate` and template authoring
	// surface it.
	if err = matcher.checkRequiredValues(); err != nil {
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

// checkRequiredValues reports an error when the matcher carries none of the
// values its type matches against. Such a matcher can never match anything, so
// it is always a template authoring mistake rather than an intentional no-op.
func (matcher *Matcher) checkRequiredValues() error {
	var empty bool
	var field string

	switch matcher.matcherType {
	case WordsMatcher:
		empty, field = len(matcher.Words) == 0, "words"
	case RegexMatcher:
		empty, field = len(matcher.Regex) == 0, "regex"
	case BinaryMatcher:
		empty, field = len(matcher.Binary) == 0, "binary"
	case StatusMatcher:
		empty, field = len(matcher.Status) == 0, "status"
	case SizeMatcher:
		empty, field = len(matcher.Size) == 0, "size"
	case DSLMatcher:
		empty, field = len(matcher.DSL) == 0, "dsl"
	case XPathMatcher:
		empty, field = len(matcher.XPath) == 0, "xpath"
	}

	if empty {
		return fmt.Errorf("matcher %s has no %s values specified", matcher.matcherType, field)
	}
	return nil
}
