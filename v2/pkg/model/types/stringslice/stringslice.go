package stringslice

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alecthomas/jsonschema"

	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// StringSlice represents a single (in-lined) or multiple string value(s).
// The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.
type StringSlice struct {
	Value interface{}
}

func New(value interface{}) StringSlice {
	return StringSlice{Value: value}
}

func (stringSlice StringSlice) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		OneOf: []*jsonschema.Type{{Type: "string"}, {Type: "array"}},
	}
	return gotType
}

func (stringSlice *StringSlice) IsEmpty() bool {
	return len(stringSlice.ToSlice()) == 0
}

func (stringSlice StringSlice) ToSlice() []string {
	switch value := stringSlice.Value.(type) {
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

func (stringSlice StringSlice) String() string {
	return strings.Join(stringSlice.ToSlice(), ", ")
}

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	result := make([]string, 0, len(marshalledSlice))
	for _, value := range marshalledSlice {
		result = append(result, stringSlice.Normalize(value))
	}
	stringSlice.Value = result
	return nil
}

func (stringSlice StringSlice) Normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (stringSlice StringSlice) MarshalYAML() (interface{}, error) {
	return stringSlice.Value, nil
}

func (stringSlice StringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}

func (stringSlice *StringSlice) UnmarshalJSON(data []byte) error {
	var marshalledValueAsString string
	var marshalledValuesAsSlice []string

	sliceMarshalError := json.Unmarshal(data, &marshalledValuesAsSlice)
	if sliceMarshalError != nil {
		stringMarshalError := json.Unmarshal(data, &marshalledValueAsString)
		if stringMarshalError != nil {
			return stringMarshalError
		}
	}

	var result []string
	switch {
	case len(marshalledValuesAsSlice) > 0:
		result = marshalledValuesAsSlice
	case !utils.IsBlank(marshalledValueAsString):
		result = strings.Split(marshalledValueAsString, ",")
	default:
		result = []string{}
	}

	values := make([]string, 0, len(result))
	for _, value := range result {
		values = append(values, stringSlice.Normalize(value))
	}
	stringSlice.Value = values
	return nil
}

func marshalStringToSlice(unmarshal func(interface{}) error) ([]string, error) {
	var marshalledValueAsString string
	var marshalledValuesAsSlice []string

	sliceMarshalError := unmarshal(&marshalledValuesAsSlice)
	if sliceMarshalError != nil {
		stringMarshalError := unmarshal(&marshalledValueAsString)
		if stringMarshalError != nil {
			return nil, stringMarshalError
		}
	}

	var result []string
	switch {
	case len(marshalledValuesAsSlice) > 0:
		result = marshalledValuesAsSlice
	case !utils.IsBlank(marshalledValueAsString):
		result = strings.Split(marshalledValueAsString, ",")
	default:
		result = []string{}
	}

	return result, nil
}
