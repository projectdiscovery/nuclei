// schema implements helper types & functions for generating better json schema
package schema

import (
	"strings"

	"github.com/invopop/jsonschema"
)

// PropertyMetadata is a metadata for a property in a schema / struct
type PropertyMetadata struct {
	PropName    string
	Description string
	PropType    string
	Example     []interface{}
	Default     any
	OneOf       []*PropertyMetadata
	RemoveRef   bool
}

// PropertyExamples returns a list of examples for a property
func PropertyExamples(values ...any) []interface{} {
	examples := []interface{}{}
	for _, value := range values {
		if value != nil {
			examples = append(examples, value)
		}
	}
	return examples
}

// PropertyExample returns a list of examples for a property
func PropertyExample(values any) []interface{} {
	return []interface{}{values}
}

// TrimmedString trims the string and returns it
func TrimmedString(value string) string {
	return strings.TrimSpace(value)
}

func MultiLine(values ...string) string {
	return strings.Join(values, "\n")
}

// ExtendSchema extends the schema with the metadata
// This could be patching or adding additional information to the schema
func ExtendSchema(metadata []PropertyMetadata, base *jsonschema.Schema) {
	for _, meta := range metadata {
		if prop, ok := base.Properties.Get(meta.PropName); ok {
			// if it has oneof, we need to add it
			if len(meta.OneOf) > 0 {
				for _, oneOf := range meta.OneOf {
					prop.OneOf = append(prop.OneOf, &jsonschema.Schema{
						Type:        oneOf.PropType,
						Description: oneOf.Description,
						Examples:    oneOf.Example,
						Default:     oneOf.Default,
					})
				}
			} else {
				if meta.PropType != "" {
					prop.Type = meta.PropType
				}
				if meta.Description != "" {
					prop.Description = meta.Description
				}
				if len(meta.Example) > 0 {
					prop.Examples = meta.Example
				}
				if meta.Default != nil {
					prop.Default = meta.Default
				}

			}
			prop.Examples = purgeNil(prop.Examples)
			if meta.RemoveRef {
				prop.Ref = ""
			}
		}
	}
}

func purgeNil(s []any) []any {
	var r []any
	for _, i := range s {
		if i != nil {
			r = append(r, i)
		}
	}
	return r
}
