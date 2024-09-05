package openapi

import (
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
)

// From: https://github.com/danielgtaylor/apisprout/blob/master/example.go

func getSchemaExample(schema *openapi3.Schema) (interface{}, bool) {
	if schema.Example != nil {
		return schema.Example, true
	}

	if schema.Default != nil {
		return schema.Default, true
	}

	if len(schema.Enum) > 0 {
		return schema.Enum[0], true
	}
	return nil, false
}

// stringFormatExample returns an example string based on the given format.
// http://json-schema.org/latest/json-schema-validation.html#rfc.section.7.3
func stringFormatExample(format string) string {
	switch format {
	case "date":
		// https://tools.ietf.org/html/rfc3339
		return "2018-07-23"
	case "date-time":
		// This is the date/time of API Sprout's first commit! :-)
		return "2018-07-23T22:58:00-07:00"
	case "time":
		return "22:58:00-07:00"
	case "email":
		return "email@example.com"
	case "hostname":
		// https://tools.ietf.org/html/rfc2606#page-2
		return "example.com"
	case "ipv4":
		// https://tools.ietf.org/html/rfc5737
		return "198.51.100.0"
	case "ipv6":
		// https://tools.ietf.org/html/rfc3849
		return "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	case "uri":
		return "https://tools.ietf.org/html/rfc3986"
	case "uri-template":
		// https://tools.ietf.org/html/rfc6570
		return "http://example.com/dictionary/{term:1}/{term}"
	case "json-pointer":
		// https://tools.ietf.org/html/rfc6901
		return "#/components/parameters/term"
	case "regex":
		// https://stackoverflow.com/q/3296050/164268
		return "/^1?$|^(11+?)\\1+$/"
	case "uuid":
		// https://www.ietf.org/rfc/rfc4122.txt
		return "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
	case "password":
		return "********"
	case "binary":
		return "sagefuzzertest"
	}
	return ""
}

// excludeFromMode will exclude a schema if the mode is request and the schema
// is read-only
func excludeFromMode(schema *openapi3.Schema) bool {
	if schema == nil {
		return true
	}

	if schema.ReadOnly {
		return true
	}
	return false
}

// isRequired checks whether a key is actually required.
func isRequired(schema *openapi3.Schema, key string) bool {
	for _, req := range schema.Required {
		if req == key {
			return true
		}
	}

	return false
}

type cachedSchema struct {
	pending bool
	out     interface{}
}

var (
	// ErrRecursive is when a schema is impossible to represent because it infinitely recurses.
	ErrRecursive = errors.New("Recursive schema")

	// ErrNoExample is sent when no example was found for an operation.
	ErrNoExample = errors.New("No example found")
)

func openAPIExample(schema *openapi3.Schema, cache map[*openapi3.Schema]*cachedSchema) (out interface{}, err error) {
	if ex, ok := getSchemaExample(schema); ok {
		return ex, nil
	}

	cached, ok := cache[schema]
	if !ok {
		cached = &cachedSchema{
			pending: true,
		}
		cache[schema] = cached
	} else if cached.pending {
		return nil, ErrRecursive
	} else {
		return cached.out, nil
	}

	defer func() {
		cached.pending = false
		cached.out = out
	}()

	// Handle combining keywords
	if len(schema.OneOf) > 0 {
		var ex interface{}
		var err error

		for _, candidate := range schema.OneOf {
			ex, err = openAPIExample(candidate.Value, cache)
			if err == nil {
				break
			}
		}
		return ex, err
	}
	if len(schema.AnyOf) > 0 {
		var ex interface{}
		var err error

		for _, candidate := range schema.AnyOf {
			ex, err = openAPIExample(candidate.Value, cache)
			if err == nil {
				break
			}
		}
		return ex, err
	}
	if len(schema.AllOf) > 0 {
		example := map[string]interface{}{}

		for _, allOf := range schema.AllOf {
			candidate, err := openAPIExample(allOf.Value, cache)
			if err != nil {
				return nil, err
			}

			value, ok := candidate.(map[string]interface{})
			if !ok {
				return nil, ErrNoExample
			}

			for k, v := range value {
				example[k] = v
			}
		}
		return example, nil
	}

	switch {
	case schema.Type.Is("boolean"):
		return true, nil
	case schema.Type.Is("number"), schema.Type.Is("integer"):
		value := 0.0

		if schema.Min != nil && *schema.Min > value {
			value = *schema.Min
			if schema.ExclusiveMin {
				if schema.Max != nil {
					// Make the value half way.
					value = (*schema.Min + *schema.Max) / 2.0
				} else {
					value++
				}
			}
		}

		if schema.Max != nil && *schema.Max < value {
			value = *schema.Max
			if schema.ExclusiveMax {
				if schema.Min != nil {
					// Make the value half way.
					value = (*schema.Min + *schema.Max) / 2.0
				} else {
					value--
				}
			}
		}

		if schema.MultipleOf != nil && int(value)%int(*schema.MultipleOf) != 0 {
			value += float64(int(*schema.MultipleOf) - (int(value) % int(*schema.MultipleOf)))
		}

		if schema.Type.Is("integer") {
			return int(value), nil
		}
		return value, nil
	case schema.Type.Is("string"):
		if ex := stringFormatExample(schema.Format); ex != "" {
			return ex, nil
		}
		example := "string"

		for schema.MinLength > uint64(len(example)) {
			example += example
		}

		if schema.MaxLength != nil && *schema.MaxLength < uint64(len(example)) {
			example = example[:*schema.MaxLength]
		}
		return example, nil
	case schema.Type.Is("array"), schema.Items != nil:
		example := []interface{}{}

		if schema.Items != nil && schema.Items.Value != nil {
			ex, err := openAPIExample(schema.Items.Value, cache)
			if err != nil {
				return nil, fmt.Errorf("can't get example for array item: %+v", err)
			}

			example = append(example, ex)

			for uint64(len(example)) < schema.MinItems {
				example = append(example, ex)
			}
		}
		return example, nil
	case schema.Type.Is("object"), len(schema.Properties) > 0:
		example := map[string]interface{}{}

		for k, v := range schema.Properties {
			if excludeFromMode(v.Value) {
				continue
			}

			ex, err := openAPIExample(v.Value, cache)
			if err == ErrRecursive {
				if isRequired(schema, k) {
					return nil, fmt.Errorf("can't get example for '%s': %+v", k, err)
				}
			} else if err != nil {
				return nil, fmt.Errorf("can't get example for '%s': %+v", k, err)
			} else {
				example[k] = ex
			}
		}

		if schema.AdditionalProperties.Has != nil && schema.AdditionalProperties.Schema != nil {
			addl := schema.AdditionalProperties.Schema.Value

			if !excludeFromMode(addl) {
				ex, err := openAPIExample(addl, cache)
				if err == ErrRecursive {
					// We just won't add this if it's recursive.
				} else if err != nil {
					return nil, fmt.Errorf("can't get example for additional properties: %+v", err)
				} else {
					example["additionalPropertyName"] = ex
				}
			}
		}
		return example, nil
	}
	return nil, ErrNoExample
}

// generateExampleFromSchema creates an example structure from an OpenAPI 3 schema
// object, which is an extended subset of JSON Schema.
//
// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.1.md#schemaObject
func generateExampleFromSchema(schema *openapi3.Schema) (interface{}, error) {
	return openAPIExample(schema, make(map[*openapi3.Schema]*cachedSchema)) // TODO: Use caching
}
