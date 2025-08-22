package fuzz

import (
	"fmt"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"gopkg.in/yaml.v3"
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
func (v *SliceOrMapSlice) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode, yaml.SequenceNode:
		return node.Decode(&v.Value)

	case yaml.MappingNode:
		// Handle as ordered map to preserve order
		tmpx := mapsutil.NewOrderedMap[string, string]()

		// Process key-value pairs in order
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				break
			}

			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			var key string
			if err := keyNode.Decode(&key); err != nil {
				continue
			}

			var value string
			if err := valueNode.Decode(&value); err != nil {
				continue
			}

			tmpx.Set(key, value)
		}
		v.KV = &tmpx
		return nil

	case yaml.AliasNode:
		return v.UnmarshalYAML(node.Alias)

	default:
		return fmt.Errorf("object can be a key:value or a string")
	}
}

// MarshalYAML implements yaml.Marshaler interface.
func (v SliceOrMapSlice) MarshalYAML() (any, error) {
	if v.KV != nil {
		return v.KV, nil
	}
	return v.Value, nil
}
