package http

import (
	"reflect"
	"slices"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestRequestJSONSchema(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Request{})
	requestSchema := reflected.Definitions["http.Request"]
	require.NotNil(t, requestSchema)

	t.Run("accepts fuzzing-only requests", func(t *testing.T) {
		require.True(t, hasRequiredAlternative(requestSchema, "fuzzing"))
	})

	t.Run("uses mappings for header examples", func(t *testing.T) {
		headers, ok := requestSchema.Properties.Get("headers")
		require.True(t, ok)
		require.NotEmpty(t, headers.Examples)
		for _, example := range headers.Examples {
			require.IsType(t, map[string]string{}, example)
		}
	})
}

func hasRequiredAlternative(schema *jsonschema.Schema, fields ...string) bool {
	for _, alternative := range schema.AnyOf {
		if slices.Equal(fields, alternative.Required) {
			return true
		}
	}
	return false
}
