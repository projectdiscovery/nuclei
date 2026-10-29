package matchers

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestMatcherJSONSchemaBindsTypeToField(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Matcher{})
	matcherSchema := reflected.Definitions["matchers.Matcher"]
	require.NotNil(t, matcherSchema)

	got := map[string]string{}
	for _, alternative := range matcherSchema.AnyOf {
		require.Len(t, alternative.Required, 2)
		require.Equal(t, "type", alternative.Required[0])
		typ, ok := alternative.Properties.Get("type")
		require.True(t, ok, "alternative %v must constrain the type", alternative.Required)
		got[typ.Const.(string)] = alternative.Required[1]
	}
	require.Equal(t, map[string]string{
		"status": "status",
		"size":   "size",
		"word":   "words",
		"regex":  "regex",
		"binary": "binary",
		"dsl":    "dsl",
		"xpath":  "xpath",
		"llm":    "prompt",
	}, got)
}
