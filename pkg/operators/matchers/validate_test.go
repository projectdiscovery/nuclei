package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	m := &Matcher{matcherType: DSLMatcher, DSL: []string{"anything"}}

	err := m.Validate()
	require.Nil(t, err, "Could not validate correct template")

	m = &Matcher{matcherType: DSLMatcher, Part: "test"}
	err = m.Validate()
	require.NotNil(t, err, "Invalid template was correctly validated")

	m = &Matcher{matcherType: XPathMatcher, XPath: []string{"//q[@id=\"foo\"]"}}

	err = m.Validate()
	require.Nil(t, err, "Could not validate correct XPath template")

	m = &Matcher{matcherType: XPathMatcher, Status: []int{123}}
	err = m.Validate()
	require.NotNil(t, err, "Invalid XPath template was correctly validated")

	m = &Matcher{matcherType: XPathMatcher, XPath: []string{"//a[@a==1]"}}
	err = m.Validate()
	require.NotNil(t, err, "Invalid XPath query was correctly validated")
}

// A matcher with none of the values its type matches against can never match, so
// it used to run silently and produce zero results with no diagnostic.
func TestMatcherRejectsMissingValues(t *testing.T) {
	cases := []struct {
		name    string
		matcher *Matcher
		field   string
	}{
		{"words", &Matcher{Type: MatcherTypeHolder{MatcherType: WordsMatcher}}, "words"},
		{"regex", &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}}, "regex"},
		{"binary", &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}}, "binary"},
		{"status", &Matcher{Type: MatcherTypeHolder{MatcherType: StatusMatcher}}, "status"},
		{"size", &Matcher{Type: MatcherTypeHolder{MatcherType: SizeMatcher}}, "size"},
		{"dsl", &Matcher{Type: MatcherTypeHolder{MatcherType: DSLMatcher}}, "dsl"},
		{"xpath", &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}}, "xpath"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.matcher.CompileMatchers()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.field)
		})
	}
}

// Guard rail: the check must reject only the empty case, so a matcher that does
// carry values still compiles.
func TestMatcherAcceptsProvidedValues(t *testing.T) {
	cases := []struct {
		name    string
		matcher *Matcher
	}{
		{"words", &Matcher{Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Words: []string{"a"}}},
		{"regex", &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: []string{"a"}}},
		{"binary", &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}, Binary: []string{"50494e47"}}},
		{"status", &Matcher{Type: MatcherTypeHolder{MatcherType: StatusMatcher}, Status: []int{200}}},
		{"size", &Matcher{Type: MatcherTypeHolder{MatcherType: SizeMatcher}, Size: []int{10}}},
		{"dsl", &Matcher{Type: MatcherTypeHolder{MatcherType: DSLMatcher}, DSL: []string{"1 == 1"}}},
		{"xpath", &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, XPath: []string{"//a"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.matcher.CompileMatchers())
		})
	}
}
