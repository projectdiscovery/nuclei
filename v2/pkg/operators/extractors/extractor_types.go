package extractors

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// ExtractorType is the type of the extractor specified
type ExtractorType int

// name:ExtractorType
const (
	// name:regex
	RegexExtractor ExtractorType = iota + 1
	// name:kval
	KValExtractor
	// name:xpath
	XPathExtractor
	// name:json
	JSONExtractor
	// name:dsl
	DSLExtractor
	limit
)

// extractorMappings is a table for conversion of extractor type from string.
var extractorMappings = map[ExtractorType]string{
	RegexExtractor: "regex",
	KValExtractor:  "kval",
	XPathExtractor: "xpath",
	JSONExtractor:  "json",
	DSLExtractor:   "dsl",
}

// GetType returns the type of the matcher
func (e *Extractor) GetType() ExtractorType {
	return e.Type.ExtractorType
}

// GetSupportedExtractorTypes returns list of supported types
func GetSupportedExtractorTypes() []ExtractorType {
	var result []ExtractorType
	for index := ExtractorType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toExtractorTypes(valueToMap string) (ExtractorType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range extractorMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid extractor type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t ExtractorType) String() string {
	return extractorMappings[t]
}

// ExtractorTypeHolder is used to hold internal type of the extractor
type ExtractorTypeHolder struct {
	ExtractorType ExtractorType `mapping:"true"`
}

func (holder ExtractorTypeHolder) JSONSchemaType() *jsonschema.Type {
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

func (holder *ExtractorTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
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

func (holder *ExtractorTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := toExtractorTypes(s)
	if err != nil {
		return err
	}

	holder.ExtractorType = computedType
	return nil
}

func (holder *ExtractorTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ExtractorType.String())
}

func (holder ExtractorTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ExtractorType.String(), nil
}
