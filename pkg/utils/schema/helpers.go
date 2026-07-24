// Package schema implements helper types & functions for generating better json schema.
package schema

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// PropertyMetadata is metadata for a property in a schema / struct.
type PropertyMetadata struct {
	PropName    string
	Description string
	PropType    string
	Example     []interface{}
	Default     any
	OneOf       []*PropertyMetadata
	RemoveRef   bool
	Deprecated  bool
}

// PropertyExamples returns a list of examples for a property.
func PropertyExamples(values ...any) []interface{} {
	examples := make([]interface{}, 0, len(values))
	for _, value := range values {
		if value != nil {
			examples = append(examples, value)
		}
	}
	return examples
}

// PropertyExample returns a single-item examples list for a property.
func PropertyExample(value any) []interface{} {
	return []interface{}{value}
}

// MultiLine joins description lines with newlines.
func MultiLine(values ...string) string {
	return strings.Join(values, "\n")
}

// ExtendSchema extends the schema with the metadata.
// This patches or adds additional information to existing properties.
func ExtendSchema(metadata []PropertyMetadata, base *jsonschema.Schema) {
	for _, meta := range metadata {
		prop, ok := base.Properties.Get(meta.PropName)
		if !ok {
			continue
		}
		if len(meta.OneOf) > 0 {
			prop.OneOf = nil
			for _, oneOf := range meta.OneOf {
				prop.OneOf = append(prop.OneOf, &jsonschema.Schema{
					Type:        oneOf.PropType,
					Description: oneOf.Description,
					Examples:    oneOf.Example,
					Default:     oneOf.Default,
				})
			}
			prop.Ref = ""
			prop.Type = ""
		} else {
			if meta.PropType != "" {
				prop.Type = meta.PropType
			}
			if meta.Description != "" {
				prop.Description = meta.Description
			}
			if len(meta.Example) > 0 {
				prop.Examples = dedupeExamples(append(prop.Examples, meta.Example...))
			}
			if meta.Default != nil {
				prop.Default = meta.Default
			}
		}
		prop.Examples = purgeNil(prop.Examples)
		if meta.RemoveRef {
			prop.Ref = ""
		}
		prop.Deprecated = meta.Deprecated
	}
}

// RequiredCombos is a list of required field combinations.
// At least one combination must be satisfied.
type RequiredCombos struct {
	RequireBase []string
	Require     []string
	required    []RequiredCombos
}

// RequireBase builds combinations of a shared base with each nested require set.
func RequireBase(base []string, requires ...RequiredCombos) RequiredCombos {
	return RequiredCombos{RequireBase: base, required: requires}
}

// Require builds a single required-fields combination.
func Require(require ...string) RequiredCombos {
	return RequiredCombos{Require: require}
}

// ApplyAnyOfRequired applies anyOf required field combinations.
func ApplyAnyOfRequired(meta []RequiredCombos, base *jsonschema.Schema) {
	if len(meta) == 0 {
		return
	}
	for _, anyOf := range meta {
		if len(anyOf.Require) == 0 && len(anyOf.RequireBase) == 0 {
			continue
		}
		if len(anyOf.RequireBase) > 0 && len(anyOf.required) > 0 {
			for _, r := range anyOf.required {
				required := sliceutil.Clone(anyOf.RequireBase)
				required = append(required, r.Require...)
				base.AnyOf = append(base.AnyOf, &jsonschema.Schema{
					Required: required,
				})
			}
		}
		if len(anyOf.Require) > 0 {
			base.AnyOf = append(base.AnyOf, &jsonschema.Schema{
				Required: anyOf.Require,
			})
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

func dedupeExamples(s []any) []any {
	seen := make(map[string]struct{}, len(s))
	var out []any
	for _, item := range s {
		if item == nil {
			continue
		}
		key := fmt.Sprintf("%#v", item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}
