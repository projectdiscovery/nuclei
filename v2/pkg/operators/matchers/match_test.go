package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestANDCondition(t *testing.T) {
	m := &Matcher{condition: ANDCondition, Words: []string{"a", "b"}}

	matched := m.MatchWords("a b")
	require.True(t, matched, "Could not match valid AND condition")

	matched = m.MatchWords("b")
	require.False(t, matched, "Could match invalid AND condition")
}

func TestORCondition(t *testing.T) {
	m := &Matcher{condition: ORCondition, Words: []string{"a", "b"}}

	matched := m.MatchWords("a b")
	require.True(t, matched, "Could not match valid OR condition")

	matched = m.MatchWords("b")
	require.True(t, matched, "Could not match valid OR condition")

	matched = m.MatchWords("c")
	require.False(t, matched, "Could match invalid OR condition")
}

func TestHexEncoding(t *testing.T) {
	m := &Matcher{Encoding: "hex", Type: "word", Part: "body", Words: []string{"50494e47"}}
	err := m.CompileMatchers()
	require.Nil(t, err, "could not compile matcher")

	matched := m.MatchWords("PING")
	require.True(t, matched, "Could not match valid Hex condition")
}
