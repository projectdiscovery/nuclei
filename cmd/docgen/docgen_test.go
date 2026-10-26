package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateDescriptionKeyName(t *testing.T) {
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"description": "root",
		"$defs": {
			"info": {
				"description": "info schema",
				"properties": {
					"description": {"type": "string", "description": "a property named description"},
					"meta": {
						"type": "object",
						"examples": [{"description": "example data"}],
						"default": {"description": "default data"},
						"additionalProperties": {"description": "map value"}
					}
				},
				"oneOf": [{"description": "branch"}],
				"items": {"description": "item"}
			}
		}
	}`), &m))

	updateDescriptionKeyName(m)

	require.Equal(t, "root", m["markdownDescription"])
	info := m["$defs"].(map[string]interface{})["info"].(map[string]interface{})
	require.Equal(t, "info schema", info["markdownDescription"])
	props := info["properties"].(map[string]interface{})
	require.NotContains(t, props, "markdownDescription")
	require.Equal(t, "a property named description", props["description"].(map[string]interface{})["markdownDescription"])
	meta := props["meta"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"description": "example data"}, meta["examples"].([]interface{})[0])
	require.Equal(t, map[string]interface{}{"description": "default data"}, meta["default"])
	require.Equal(t, "map value", meta["additionalProperties"].(map[string]interface{})["markdownDescription"])
	require.Equal(t, "branch", info["oneOf"].([]interface{})[0].(map[string]interface{})["markdownDescription"])
	require.Equal(t, "item", info["items"].(map[string]interface{})["markdownDescription"])
}
