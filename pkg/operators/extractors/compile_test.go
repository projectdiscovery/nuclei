package extractors

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCompileExtractorsRequiresValues(t *testing.T) {
	tests := []struct {
		typ    string
		field  string
		values string
	}{
		{"regex", "regex", `["hello"]`},
		{"kval", "kval", `["header"]`},
		{"json", "json", `[".value"]`},
		{"xpath", "xpath", `["//a"]`},
		{"dsl", "dsl", `["body"]`},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			for _, suffix := range []struct{ name, yaml string }{
				{"omitted", ""},
				{"null", tt.field + ": null\n"},
				{"empty", tt.field + ": []\n"},
			} {
				t.Run(suffix.name, func(t *testing.T) {
					var operator Extractor
					require.NoError(t, yaml.Unmarshal([]byte("type: "+tt.typ+"\n"+suffix.yaml), &operator))
					require.ErrorContains(t, operator.CompileExtractors(), fmt.Sprintf("%s extractor requires at least one %s value", tt.typ, tt.field))
				})
			}
			t.Run("valid", func(t *testing.T) {
				var operator Extractor
				require.NoError(t, yaml.Unmarshal([]byte("type: "+tt.typ+"\n"+tt.field+": "+tt.values), &operator))
				require.NoError(t, operator.CompileExtractors())
			})
		})
	}
}

func TestCompileExtractorsRequiresValuesForSelectedType(t *testing.T) {
	e := &Extractor{
		Type: ExtractorTypeHolder{ExtractorType: RegexExtractor},
		KVal: []string{"header"},
	}
	require.ErrorContains(t, e.CompileExtractors(), "regex extractor requires at least one regex value")
}
