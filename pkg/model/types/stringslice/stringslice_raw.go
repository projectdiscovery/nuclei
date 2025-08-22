package stringslice

import "gopkg.in/yaml.v3"

type RawStringSlice struct {
	StringSlice
}

func NewRawStringSlice(value interface{}) *RawStringSlice {
	return &RawStringSlice{StringSlice: StringSlice{Value: value}}
}

func (rawStringSlice *RawStringSlice) Normalize(value string) string {
	return value
}

func (rawStringSlice *RawStringSlice) UnmarshalYAML(node *yaml.Node) error {
	result, err := UnmarshalYAMLNode(node, rawStringSlice)
	if err != nil {
		return err
	}
	rawStringSlice.Value = result
	return nil
}

func (rawStringSlice RawStringSlice) JSONSchemaAlias() any {
	return StringOrSlice("")
}
