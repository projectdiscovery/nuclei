package stringslice

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// NormalizedStringSlice represents a single (in-lined) or multiple string value(s).
// The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.
// All strings will be converted to lowercase.
type NormalizedStringSlice struct {
	Value interface{}
}

func (stringSlice NormalizedStringSlice) JSONSchemaType() *jsonschema.Type {
	return stringSliceJSONSchemaType()
}

func (stringSlice NormalizedStringSlice) IsEmpty() bool {
	return len(stringSlice.ToSlice()) == 0
}

func (stringSlice NormalizedStringSlice) ToSlice() []string {
	return toSlice(stringSlice.Value)
}

func (stringSlice NormalizedStringSlice) String() string {
	return strings.Join(stringSlice.ToSlice(), ", ")
}

func (stringSlice *NormalizedStringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	unmarshalledSlice, err := marshalYAMLStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	stringSlice.Value = normalizeStringSlice(unmarshalledSlice, false)
	return nil
}

func (stringSlice NormalizedStringSlice) MarshalYAML() (interface{}, error) {
	return stringSlice.Value, nil
}

func (stringSlice NormalizedStringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}

func (stringSlice *NormalizedStringSlice) UnmarshalJSON(data []byte) error {
	unmarshalledSlice, err := unmarshalJSONStringToSlice(data)
	if err != nil {
		return err
	}

	stringSlice.Value = normalizeStringSlice(unmarshalledSlice, false)
	return nil
}
