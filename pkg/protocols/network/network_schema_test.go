package network

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestRequestJSONSchemaRequiresHost(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Request{})
	requestSchema := reflected.Definitions["network.Request"]
	require.NotNil(t, requestSchema)
	require.Len(t, requestSchema.AnyOf, 1)
	require.Equal(t, []string{"host"}, requestSchema.AnyOf[0].Required)
}

func TestRequestJSONSchemaHostExamplesAreArrays(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Request{})
	requestSchema := reflected.Definitions["network.Request"]
	require.NotNil(t, requestSchema)
	host, ok := requestSchema.Properties.Get("host")
	require.True(t, ok)
	require.NotEmpty(t, host.Examples)
	for _, example := range host.Examples {
		require.IsType(t, []string{}, example)
	}
}
