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

func TestCompileExtractorsRejectsMisappliedGroup(t *testing.T) {
	invalidTypes := []string{"kval", "json", "xpath", "dsl"}
	for _, typ := range invalidTypes {
		t.Run(typ, func(t *testing.T) {
			rawYAML := fmt.Sprintf("type: %s\n%s:\n  - test\ngroup: 1\n", typ, typ)
			var extractor Extractor
			require.NoError(t, yaml.Unmarshal([]byte(rawYAML), &extractor))
			err := extractor.CompileExtractors()
			require.Error(t, err)
			require.ErrorContains(t, err, fmt.Sprintf("group is supported only for 'regex' extractors (not '%s')", typ))
		})
	}

	t.Run("valid regex group", func(t *testing.T) {
		rawYAML := "type: regex\nregex:\n  - '([a-z]+)'\ngroup: 1\n"
		var extractor Extractor
		require.NoError(t, yaml.Unmarshal([]byte(rawYAML), &extractor))
		require.NoError(t, extractor.CompileExtractors())
	})
}

func TestCompileExtractorsRejectsMisappliedAttribute(t *testing.T) {
	invalidTypes := []string{"regex", "kval", "json", "dsl"}
	for _, typ := range invalidTypes {
		t.Run(typ, func(t *testing.T) {
			rawYAML := fmt.Sprintf("type: %s\n%s:\n  - test\nattribute: href\n", typ, typ)
			var extractor Extractor
			require.NoError(t, yaml.Unmarshal([]byte(rawYAML), &extractor))
			err := extractor.CompileExtractors()
			require.Error(t, err)
			require.ErrorContains(t, err, fmt.Sprintf("attribute is supported only for 'xpath' extractors (not '%s')", typ))
		})
	}

	t.Run("valid xpath attribute", func(t *testing.T) {
		rawYAML := "type: xpath\nxpath:\n  - '//a'\nattribute: href\n"
		var extractor Extractor
		require.NoError(t, yaml.Unmarshal([]byte(rawYAML), &extractor))
		require.NoError(t, extractor.CompileExtractors())
	})
}
