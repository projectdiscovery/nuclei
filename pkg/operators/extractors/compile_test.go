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

func TestCompileExtractorsKeepsGroupOnNonRegex(t *testing.T) {
	cases := []string{
		"type: json\njson:\n  - '.experiment_id'\ngroup: 1\n",
		"type: kval\nkval:\n  - server\ngroup: 1\n",
		"type: regex\nregex:\n  - '([a-z]+)'\ngroup: 1\n",
	}
	for _, rawYAML := range cases {
		var extractor Extractor
		require.NoError(t, yaml.Unmarshal([]byte(rawYAML), &extractor))
		require.NoError(t, extractor.CompileExtractors())
	}
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

func TestCompileExtractorsRejectsInvalidXPath(t *testing.T) {
	tests := []struct {
		name    string
		xpath   string
		wantErr string
	}{
		{
			name:    "unclosed bracket",
			xpath:   "//a[",
			wantErr: `could not compile xpath "//a[":`,
		},
		{
			name:    "undefined function",
			xpath:   "unknown-function()",
			wantErr: `could not compile xpath "unknown-function()":`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extractor{
				Type:  ExtractorTypeHolder{ExtractorType: XPathExtractor},
				XPath: []string{tt.xpath},
			}
			err := e.CompileExtractors()
			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCompileExtractorsAcceptsValidXPath(t *testing.T) {
	e := &Extractor{
		Type:  ExtractorTypeHolder{ExtractorType: XPathExtractor},
		XPath: []string{"//a", "/html/body/div/p[2]/a"},
	}
	require.NoError(t, e.CompileExtractors())
}

func TestCompileExtractorsIgnoresXPathOnOtherTypes(t *testing.T) {
	e := &Extractor{
		Type:  ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex: []string{"a"},
		XPath: []string{"//a["},
	}
	require.NoError(t, e.CompileExtractors())
}
