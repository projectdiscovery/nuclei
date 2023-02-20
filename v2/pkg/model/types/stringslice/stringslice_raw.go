package stringslice

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// RawStringSlice represents a single (in-lined) or multiple string value(s).
// The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.
type RawStringSlice struct {
	Value interface{}
}

func (stringSlice RawStringSlice) JSONSchemaType() *jsonschema.Type {
	return stringSliceJSONSchemaType()
}

func (stringSlice RawStringSlice) ToSlice() []string {
	return toSlice(stringSlice.Value)
}

func (stringSlice RawStringSlice) IsEmpty() bool {
	return len(stringSlice.ToSlice()) == 0
}

func (stringSlice RawStringSlice) String() string {
	return strings.Join(stringSlice.ToSlice(), ", ")
}

func (stringSlice RawStringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}

func (stringSlice *RawStringSlice) UnmarshalJSON(data []byte) error {
	unmarshalledSlice, err := unmarshalJSONStringToSlice(data)
	if err != nil {
		return err
	}

	stringSlice.Value = normalizeStringSlice(unmarshalledSlice, true)
	return nil
}

func (stringSlice RawStringSlice) MarshalYAML() (interface{}, error) {
	return stringSlice.Value, nil
}

func (stringSlice *RawStringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	unmarshalledSlice, err := marshalYAMLStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	stringSlice.Value = normalizeStringSlice(unmarshalledSlice, true)
	return nil
}
