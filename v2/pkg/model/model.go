package model

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"strings"
)

type Info struct {
	Name           string
	Authors        StringSlice `yaml:"author"`
	Tags           StringSlice `yaml:"tags"`
	Description    string
	Reference      StringSlice            `yaml:"reference"`
	SeverityHolder goflags.SeverityHolder `yaml:"severity"`
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
	}
	panic("Illegal State: StringSlice holds non-string value(s)")
}

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	var slice []string

	err := unmarshal(&slice)
	if err != nil {
		err := unmarshal(&str)
		if err != nil {
			return err
		}
	}

	var result []string
	var split []string
	if len(slice) > 0 {
		split = slice
	} else if strings.TrimSpace(str) != "" {
		split = strings.Split(str, ",")
	}

	for _, value := range split {
		result = append(result, strings.ToLower(strings.TrimSpace(value)))
	}
	stringSlice.Value = result
	return nil
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
