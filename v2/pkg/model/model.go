package model

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

type Info struct {
	Name           string                  `json:"name" yaml:"name"`
	Authors        StringSlice             `json:"author" yaml:"author"`
	Tags           StringSlice             `json:"tags" yaml:"tags"`
	Description    string                  `json:"description" yaml:"description"`
	Reference      StringSlice             `json:"reference" yaml:"reference"`
	SeverityHolder severity.SeverityHolder `json:"severity" yaml:"severity"`
}

// StringSlice represents a single (in-lined) or multiple string value(s).
// The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.
type StringSlice struct {
	Value interface{}
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

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	result := make([]string, len(marshalledSlice))
	//nolint:gosimple,nolintlint //cannot be replaced with result = append(result, slices...) because the values are being normalized
	for _, value := range marshalledSlice {
		result = append(result, strings.ToLower(strings.TrimSpace(value))) // TODO do we need to introduce RawStringSlice and/or NormalizedStringSlices?
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
	} else if utils.IsNotBlank(marshalledValueAsString) {
		result = strings.Split(marshalledValueAsString, ",")
	} else {
		result = []string{}
	}

	return result, nil
}

func (stringSlice StringSlice) MarshalYAML() (interface{}, error) {
	return yaml.Marshal(stringSlice.Value)
}

func (stringSlice StringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}
