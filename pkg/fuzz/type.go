package fuzz

import (
	"fmt"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"gopkg.in/yaml.v2"
)

var (
	_ json.JSONCodec   = &SliceOrMapSlice{}
	_ yaml.Marshaler   = &SliceOrMapSlice{}
	_ yaml.Unmarshaler = &SliceOrMapSlice{}
)

type ValueOrKeyValue struct {
	Key   string
	Value string

	OriginalPayload string
}

func (v *ValueOrKeyValue) IsKV() bool {
	return v.Key != ""
}

type SliceOrMapSlice struct {
	Value []string
	KV    *mapsutil.OrderedMap[string, string]
}

func (v SliceOrMapSlice) JSONSchemaExtend(schema *jsonschema.Schema) *jsonschema.Schema {
	schema = &jsonschema.Schema{
		Title:       schema.Title,
		Description: schema.Description,
		Type:        "array",
		Items: &jsonschema.Schema{
			OneOf: []*jsonschema.Schema{
				{
					Type: "string",
				},
				{
					Type: "object",
				},
			},
		},
	}
	return schema
}

func (v SliceOrMapSlice) JSONSchema() *jsonschema.Schema {
	gotType := &jsonschema.Schema{
		Title:       "Payloads of Fuzz Rule",
		Description: "Payloads to perform fuzzing substitutions with.",
		Type:        "array",
		Items: &jsonschema.Schema{
			OneOf: []*jsonschema.Schema{
				{
					Type: "string",
				},
				{
					Type: "object",
				},
			},
		},
	}
	return gotType
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (v *SliceOrMapSlice) UnmarshalJSON(data []byte) error {
	// try to unmashal as a string and fallback to map
	if err := json.Unmarshal(data, &v.Value); err == nil {
		return nil
	}
	err := json.Unmarshal(data, &v.KV)
	if err != nil {
		return fmt.Errorf("object can be a key:value or a string")
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (v SliceOrMapSlice) MarshalJSON() ([]byte, error) {
	if v.KV != nil {
		return json.Marshal(v.KV)
	}
	return json.Marshal(v.Value)
}

// UnmarshalYAML implements yaml.Unmarshaler interface.
func (v *SliceOrMapSlice) UnmarshalYAML(callback func(interface{}) error) error {
	// try to unmarshal it as a string and fallback to map
	if err := callback(&v.Value); err == nil {
		return nil
	}

	// try with a mapslice
	var node yaml.MapSlice
	if err := callback(&node); err == nil {
		tmpx := mapsutil.NewOrderedMap[string, string]()
		// preserve order
		for _, v := range node {
			tmpx.Set(v.Key.(string), v.Value.(string))
		}
		v.KV = &tmpx
		return nil
	}
	return fmt.Errorf("object can be a key:value or a string")
}

// MarshalYAML implements yaml.Marshaler interface.
func (v SliceOrMapSlice) MarshalYAML() (any, error) {
	if v.KV != nil {
		return v.KV, nil
	}
	return v.Value, nil
}
