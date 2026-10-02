package operators

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A field that only one extractor type reads is dropped without complaint when
// it is left on another type, so the template compiles and runs and the
// extractor silently returns whatever its own type collects. This checks that
// the misconfiguration is reported through Operators.Compile, which is the
// entry point template loading uses, instead of being swallowed.
func TestOperatorsCompileRejectsExtractorFieldOnWrongType(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		contains string
	}{
		{
			name: "attribute on a json extractor",
			yaml: `
extractors:
  - type: json
    json:
      - ".name"
    attribute: href
`,
			contains: "attribute is supported only for 'xpath' extractors (not 'json')",
		},
		{
			name: "attribute on a kval extractor",
			yaml: `
extractors:
  - type: kval
    kval:
      - server
    attribute: href
`,
			contains: "attribute is supported only for 'xpath' extractors (not 'kval')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var operators Operators
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), &operators))

			err := operators.Compile()
			require.ErrorContains(t, err, "could not compile extractor")
			require.ErrorContains(t, err, tt.contains)
		})
	}
}

// The documented combinations must keep working end to end.
func TestOperatorsCompileAcceptsExtractorFieldOnOwnerType(t *testing.T) {
	yamlTemplates := []string{
		`
extractors:
  - type: xpath
    xpath:
      - "//a"
    attribute: href
`,
		`
extractors:
  - type: json
    json:
      - ".name"
`,
	}

	for _, document := range yamlTemplates {
		var operators Operators
		require.NoError(t, yaml.Unmarshal([]byte(document), &operators))
		require.NoError(t, operators.Compile())
	}
}

func TestOperatorsCompileAcceptsEmptyFieldsOnNonOwnerTypes(t *testing.T) {
	// Zero values are how YAML expresses "not set", so they must never trip
	// the ownership check.
	document := `
extractors:
  - type: json
    json:
      - ".name"
    attribute: ""
`
	var operators Operators
	require.NoError(t, yaml.Unmarshal([]byte(document), &operators))
	require.NoError(t, operators.Compile())
}

// `group` on a non-regex extractor is a no-op that real templates rely on
// staying tolerated, so Operators.Compile must keep accepting it.
func TestOperatorsCompileAcceptsGroupOnNonRegexType(t *testing.T) {
	document := `
extractors:
  - type: json
    name: EXPERIMENT_ID
    group: 1
    json:
      - ".experiment_id"
`
	var operators Operators
	require.NoError(t, yaml.Unmarshal([]byte(document), &operators))
	require.NoError(t, operators.Compile())
}
