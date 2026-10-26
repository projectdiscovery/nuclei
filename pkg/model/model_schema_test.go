package model

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestInfoJSONSchemaObjectExamples(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Info{})
	infoSchema := reflected.Definitions["model.Info"]
	require.NotNil(t, infoSchema)
	for _, name := range []string{"metadata", "classification"} {
		property, ok := infoSchema.Properties.Get(name)
		require.True(t, ok, name)
		require.NotEmpty(t, property.Examples, name)
		for _, example := range property.Examples {
			require.IsType(t, map[string]any{}, example, "%s is an object, so its examples must be objects", name)
		}
	}
}
