package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Info contains metadata information about a template
type Info struct {
	// description: |
	//   Name should be good short summary that identifies what the template does.
	//
	// examples:
	//   - value: "\"bower.json file disclosure\""
	//   - value: "\"Nagios Default Credentials Check\""
	Name string `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,example=Nagios Default Credentials Check"`
	// description: |
	//   Author of the template.
	//
	//   Multiple values can also be specified separated by commas.
	// examples:
	//   - value: "\"<username>\""
	Authors StringSlice `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,example=username"`
	// description: |
	//   Any tags for the template.
	//
	//   Multiple values can also be specified separated by commas.
	//
	// examples:
	//   - name: Example tags
	//     value: "\"cve,cve2019,grafana,auth-bypass,dos\""
	Tags StringSlice `json:"tags,omitempty" yaml:"tags,omitempty" jsonschema:"title=tags of the template,description=Any tags for the template"`
	// description: |
	//   Description of the template.
	//
	//   You can go in-depth here on what the template actually does.
	//
	// examples:
	//   - value: "\"Bower is a package manager which stores packages informations in bower.json file\""
	//   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,example=Bower is a package manager which stores packages informations in bower.json file"`
	// description: |
	//   References for the template.
	//
	//   This should contain links relevant to the template.
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Reference StringSlice `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// description: |
	//   Severity of the template.
	//
	// values:
	//   - info
	//   - low
	//   - medium
	//   - high
	//   - critical
	SeverityHolder severity.SeverityHolder `json:"severity,omitempty" yaml:"severity,omitempty"`
	// description: |
	//   AdditionalFields regarding metadata of the template.
	//
	// examples:
	//   - value: >
	//       map[string]string{"customField1":"customValue1"}
	AdditionalFields map[string]string `json:"additional-fields,omitempty" yaml:"additional-fields,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template"`
}

// StringSlice represents a single (in-lined) or multiple string value(s).
// The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.
type StringSlice struct {
	Value interface{}
}

func (stringSlice StringSlice) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		OneOf: []*jsonschema.Type{{Type: "string"}, {Type: "array"}},
	}
	return gotType
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

func (stringSlice StringSlice) String() string {
	return strings.Join(stringSlice.ToSlice(), ", ")
}

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	result := make([]string, 0, len(marshalledSlice))
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
	return stringSlice.Value, nil
}

func (stringSlice StringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}
