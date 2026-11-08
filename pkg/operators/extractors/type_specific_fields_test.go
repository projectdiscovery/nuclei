package extractors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A field that only one extractor type reads is silently ignored when it is
// left on any other type. The extractor still runs and returns whatever its own
// type collects, so the result is indistinguishable from "nothing matched" and
// the template under-reports findings without any error.
func TestCompileExtractorsRejectsFieldOnWrongType(t *testing.T) {
	tests := []struct {
		name      string
		extractor *Extractor
		expected  string
	}{
		{
			name: "attribute on a json extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: JSONExtractor},
				JSON:      []string{".name"},
				Attribute: "href",
			},
			expected: "attribute is supported only for 'xpath' extractors (not 'json')",
		},
		{
			name: "attribute on a regex extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: RegexExtractor},
				Regex:     []string{`href="([^"]+)"`},
				Attribute: "href",
			},
			expected: "attribute is supported only for 'xpath' extractors (not 'regex')",
		},
		{
			name: "attribute on a kval extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: KValExtractor},
				KVal:      []string{"server"},
				Attribute: "href",
			},
			expected: "attribute is supported only for 'xpath' extractors (not 'kval')",
		},
		{
			name: "attribute on a dsl extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: DSLExtractor},
				DSL:       []string{"to_lower(body)"},
				Attribute: "href",
			},
			expected: "attribute is supported only for 'xpath' extractors (not 'dsl')",
		},
		{
			name: "attribute on an llm extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: LLMExtractor},
				Schema:    map[string]string{"value": "string"},
				Attribute: "href",
			},
			expected: "attribute is supported only for 'xpath' extractors (not 'llm')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.EqualError(t, tt.extractor.CompileExtractors(), tt.expected)
		})
	}
}

// The owner type must keep working, and zero values are how YAML spells
// "not set", so they must never trip the ownership check.
func TestCompileExtractorsAcceptsFieldOnOwnerType(t *testing.T) {
	tests := []struct {
		name      string
		extractor *Extractor
	}{
		{
			name: "attribute on an xpath extractor",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: XPathExtractor},
				XPath:     []string{"//a"},
				Attribute: "href",
			},
		},
		{
			name: "empty attribute is unset and needs no owner",
			extractor: &Extractor{
				Type:      ExtractorTypeHolder{ExtractorType: JSONExtractor},
				JSON:      []string{".name"},
				Attribute: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.extractor.CompileExtractors())
		})
	}
}

// `group` is a no-op outside regex extractors in exactly the same way, but it is
// deliberately not enforced.
//
// A survey of all 14,029 templates in nuclei-templates found 17 extractors that
// set `group` on a json or kval extractor, including published CVE detections
// such as CVE-2024-3848:
//
//	extractors:
//	  - type: json
//	    name: EXPERIMENT_ID
//	    group: 1
//	    json:
//	      - '.experiment_id'
//
// Rejecting those would break real templates, so this test pins the current
// behaviour to stop the ownership rule from being extended to `group` before
// those templates are corrected.
func TestCompileExtractorsToleratesGroupOnNonRegexType(t *testing.T) {
	extractors := []*Extractor{
		{
			Type:       ExtractorTypeHolder{ExtractorType: JSONExtractor},
			JSON:       []string{".experiment_id"},
			RegexGroup: 1,
		},
		{
			Type:       ExtractorTypeHolder{ExtractorType: KValExtractor},
			KVal:       []string{"server"},
			RegexGroup: 1,
		},
	}

	for _, e := range extractors {
		require.NoError(t, e.CompileExtractors(), e.GetType().String())
	}

	// The group is still ignored rather than honoured.
	grouped := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: JSONExtractor},
		JSON:       []string{".name"},
		RegexGroup: 1,
	}
	require.NoError(t, grouped.CompileExtractors())
	require.Equal(t, map[string]struct{}{"value": {}}, grouped.ExtractJSON(`{"name":"value"}`))
}

// The misapplied-field check must not pre-empt the more useful "this extractor
// type has no values" error.
func TestCompileExtractorsReportsMissingValuesBeforeMisappliedField(t *testing.T) {
	e := &Extractor{
		Type:      ExtractorTypeHolder{ExtractorType: JSONExtractor},
		Attribute: "href",
	}
	require.ErrorContains(t, e.CompileExtractors(), "json extractor requires at least one json value")
}

// Every supported extractor type compiles when no field is misapplied.
func TestCompileExtractorsUnchangedForValidExtractors(t *testing.T) {
	extractors := []*Extractor{
		{Type: ExtractorTypeHolder{ExtractorType: RegexExtractor}, Regex: []string{`(\d+)`}},
		{Type: ExtractorTypeHolder{ExtractorType: RegexExtractor}, Regex: []string{`(\w+)@(\w+)`}, RegexGroup: 1},
		{Type: ExtractorTypeHolder{ExtractorType: KValExtractor}, KVal: []string{"content_type"}},
		{Type: ExtractorTypeHolder{ExtractorType: JSONExtractor}, JSON: []string{".name"}},
		{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"//a"}},
		{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"//a"}, Attribute: "href"},
		{Type: ExtractorTypeHolder{ExtractorType: DSLExtractor}, DSL: []string{"to_lower(body)"}},
	}
	for _, e := range extractors {
		require.NoError(t, e.CompileExtractors(), e.GetType().String())
	}
}

// A misapplied attribute used to be dropped without complaint, so the json
// extractor below returned the raw value even though the template author asked
// for an attribute. This locks in that the configuration is now rejected.
func TestCompileExtractorsMisappliedAttributeUsedToSilentlyChangeResult(t *testing.T) {
	e := &Extractor{
		Type:      ExtractorTypeHolder{ExtractorType: JSONExtractor},
		JSON:      []string{".name"},
		Attribute: "href",
	}
	require.Error(t, e.CompileExtractors())
	require.Empty(t, e.jsonCompiled)
}
