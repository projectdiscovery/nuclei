package extractors

import (
	"encoding/json"

	"github.com/alecthomas/jsonschema"
)

// TypeHolder is used to hold internal type of the extractor
type TypeHolder struct {
	ExtractorType ExtractorType
}

func (holder TypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the extractor",
		Description: "Type of the extractor",
	}
	for _, types := range GetSupportedExtractorTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *TypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toExtractorTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.ExtractorType = computedType
	return nil
}

func (holder *TypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ExtractorType.String())
}

func (holder TypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ExtractorType.String(), nil
}
