package matchers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCompileMatchersRequiresValues(t *testing.T) {
	tests := []struct {
		typ    string
		field  string
		values string
	}{
		{"word", "words", `["hello"]`},
		{"regex", "regex", `["hello"]`},
		{"binary", "binary", `["00"]`},
		{"status", "status", `[200]`},
		{"size", "size", `[0]`},
		{"dsl", "dsl", `["true"]`},
		{"xpath", "xpath", `["//a"]`},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			for _, suffix := range []struct{ name, yaml string }{
				{"omitted", ""},
				{"null", tt.field + ": null\n"},
				{"empty", tt.field + ": []\n"},
			} {
				t.Run(suffix.name, func(t *testing.T) {
					var operator Matcher
					require.NoError(t, yaml.Unmarshal([]byte("type: "+tt.typ+"\n"+suffix.yaml), &operator))
					require.ErrorContains(t, operator.CompileMatchers(), fmt.Sprintf("%s matcher requires at least one %s value", tt.typ, tt.field))
				})
			}
			t.Run("valid", func(t *testing.T) {
				var operator Matcher
				require.NoError(t, yaml.Unmarshal([]byte("type: "+tt.typ+"\n"+tt.field+": "+tt.values), &operator))
				require.NoError(t, operator.CompileMatchers())
			})
		})
	}
}

func TestCompileMatchersAllowsEmptyStringValue(t *testing.T) {
	m := &Matcher{
		Type:  MatcherTypeHolder{MatcherType: WordsMatcher},
		Words: []string{""},
	}
	require.NoError(t, m.CompileMatchers())
	matched, _ := m.MatchWords("body", nil)
	require.True(t, matched)
}
