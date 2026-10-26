package extractors

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

func TestExtractorJSONSchemaBindsTypeToField(t *testing.T) {
	reflected := (&jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			return t.String()
		},
	}).Reflect(&Extractor{})
	extractorSchema := reflected.Definitions["extractors.Extractor"]
	require.NotNil(t, extractorSchema)

	got := map[string]string{}
	for _, alternative := range extractorSchema.AnyOf {
		require.Len(t, alternative.Required, 2)
		require.Equal(t, "type", alternative.Required[0])
		typ, ok := alternative.Properties.Get("type")
		require.True(t, ok, "alternative %v must constrain the type", alternative.Required)
		got[typ.Const.(string)] = alternative.Required[1]
	}
	require.Equal(t, map[string]string{
		"regex": "regex",
		"kval":  "kval",
		"json":  "json",
		"xpath": "xpath",
		"dsl":   "dsl",
		"llm":   "prompt",
	}, got)
}
