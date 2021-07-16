package model

import (
	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"strings"
)

type Info struct {
	Name           string
	Authors        StringSlice `yaml:"author"`
	Tags           StringSlice `yaml:"tags"`
	Description    string
	Reference      StringSlice             `yaml:"reference"`
	SeverityHolder severity.SeverityHolder `yaml:"severity"`
}

type StringSlice struct {
	Value interface{}
}

func (stringSlice *StringSlice) IsEmpty() bool {
	return utils.IsEmpty(stringSlice.Value)
}

func (stringSlice StringSlice) ToSlice() []string {
	switch value := stringSlice.Value.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case nil:
		return []string{}
	}
	panic("Illegal State: StringSlice holds non-string value(s)")
}

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	result := make([]string, len(marshalledSlice))
	for _, value := range marshalledSlice {
		result = append(result, strings.ToLower(strings.TrimSpace(value)))
	}
	stringSlice.Value = result
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
	if len(marshalledValuesAsSlice) > 0 {
		result = marshalledValuesAsSlice
	} else if utils.IsNotEmpty(marshalledValueAsString) {
		result = strings.Split(marshalledValueAsString, ",")
	} else {
		result = []string{}
	}

	return result, nil
}

func (stringSlice StringSlice) MarshalYAML() (interface{}, error) {
	switch value := stringSlice.Value.(type) {
	case string:
		return value, nil
	case []string:
		return strings.Join(value, ", "), nil
	default:
		panic("Unsupported type")
	}
}
