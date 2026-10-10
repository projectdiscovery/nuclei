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

func TestCompileExtractorsXPath(t *testing.T) {
	tests := []struct {
		name    string
		queries []string
		invalid string
	}{
		{name: "element", queries: []string{"//a"}},
		{name: "attribute", queries: []string{"//a/@href"}},
		{name: "predicate", queries: []string{"//a[contains(@href, 'example')]"}},
		{name: "namespace", queries: []string{"//ns:item"}},
		{name: "multiple", queries: []string{"//a", "//p/text()"}},
		{name: "unclosed predicate", queries: []string{"//a["}, invalid: "//a["},
		{name: "unknown function", queries: []string{"unknown-function()"}, invalid: "unknown-function()"},
		{name: "invalid second query", queries: []string{"//a", "//p["}, invalid: "//p["},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extractor{
				Type:  ExtractorTypeHolder{ExtractorType: XPathExtractor},
				XPath: tt.queries,
			}
			err := e.CompileExtractors()
			if tt.invalid != "" {
				require.ErrorContains(t, err, fmt.Sprintf("could not compile xpath %q", tt.invalid))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCompileExtractorsXPathExtraction(t *testing.T) {
	for _, corpus := range []string{
		`<html><body><a href="example">link</a></body></html>`,
		`<?xml version="1.0"?><root><a href="example">link</a></root>`,
	} {
		e := &Extractor{
			Type:      ExtractorTypeHolder{ExtractorType: XPathExtractor},
			XPath:     []string{"//a"},
			Attribute: "href",
		}
		require.NoError(t, e.CompileExtractors())
		require.Equal(t, map[string]struct{}{"example": {}}, e.ExtractXPath(corpus))
	}
}
