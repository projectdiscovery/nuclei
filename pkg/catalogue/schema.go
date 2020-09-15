package catalogue

import (
	"fmt"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v2"
)

// unmarshalForValidation YAML to map[string]interface{} instead of map[interface{}]interface{}.
// Taken from: https://github.com/go-yaml/yaml/issues/139
func unmarshalForValidation(in []byte, out interface{}) error {
	var res interface{}

	if err := yaml.Unmarshal(in, &res); err != nil {
		return err
	}
	*out.(*interface{}) = cleanupMapValue(res)

	return nil
}

func cleanupInterfaceArray(in []interface{}) []interface{} {
	res := make([]interface{}, len(in))
	for i, v := range in {
		res[i] = cleanupMapValue(v)
	}
	return res
}

func cleanupInterfaceMap(in map[interface{}]interface{}) map[string]interface{} {
	res := make(map[string]interface{})
	for k, v := range in {
		res[fmt.Sprintf("%v", k)] = cleanupMapValue(v)
	}
	return res
}

func cleanupMapValue(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		return cleanupInterfaceArray(v)
	case map[interface{}]interface{}:
		return cleanupInterfaceMap(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

var schemaLoader = gojsonschema.NewBytesLoader([]byte(`{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://projectdiscovery.io/nuclei-template.schema.json",
  "title": "Nuclei Templates YAML format validation",
  "description": "A validation format for validating nuclei-template files.",
  "required": [ "id", "info" ],
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-z0-9\\-]{1,32}$"
    },
    "info": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "author": {
          "type": "string"
        },
        "severity": {
          "type": "string"
        },
        "description": {
          "type": "string"
        }
      }
    }
  }
}`))
