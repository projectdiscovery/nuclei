package stringslice

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

func stringSliceJSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		OneOf: []*jsonschema.Type{{Type: "string"}, {Type: "array"}},
	}
	return gotType
}

func toSlice(sliceValue interface{}) []string {
	switch value := sliceValue.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case nil:
		return []string{}
	default:
		panic(fmt.Sprintf("Unexpected StringSlice type: '%T'", value))
	}
}

// normalize strings to lowercase if caseSensitive is false
func normalize(value string, caseSensitive bool) string {
	normalized := strings.TrimSpace(value)
	if caseSensitive {
		return normalized
	}
	return strings.ToLower(normalized)
}

func normalizeStringSlice(values []string, caseSensitive bool) []string {
	normalizedValues := make([]string, 0, len(values))
	for i := range values {
		normalizedValues = append(normalizedValues, normalize(values[i], caseSensitive))
	}
	return normalizedValues
}

func marshalYAMLStringToSlice(unmarshal func(interface{}) error) ([]string, error) {
	var unmarshalledValuesAsSlice []string
	if sliceUnmarshalError := unmarshal(&unmarshalledValuesAsSlice); sliceUnmarshalError == nil {
		return unmarshalledValuesAsSlice, nil
	}

	var unmarshalledValueAsString string
	if stringUnmarshalError := unmarshal(&unmarshalledValueAsString); stringUnmarshalError != nil {
		return nil, stringUnmarshalError
	}

	if !utils.IsBlank(unmarshalledValueAsString) {
		return strings.Split(unmarshalledValueAsString, ","), nil
	}
	return []string{}, nil
}

func unmarshalJSONStringToSlice(data []byte) ([]string, error) {
	var unmarshalledValuesAsSlice []string
	if sliceUnmarshalError := json.Unmarshal(data, &unmarshalledValuesAsSlice); sliceUnmarshalError == nil {
		return unmarshalledValuesAsSlice, nil
	}

	var unmarshalledValueAsString string
	if stringUnmarshalError := json.Unmarshal(data, &unmarshalledValueAsString); stringUnmarshalError != nil {
		return nil, stringUnmarshalError
	}

	if !utils.IsBlank(unmarshalledValueAsString) {
		return strings.Split(unmarshalledValueAsString, ","), nil
	}
	return []string{}, nil
}
