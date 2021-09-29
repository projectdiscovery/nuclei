package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestANDCondition(t *testing.T) {
	m := &Matcher{condition: ANDCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b", nil)
	require.True(t, isMatched, "Could not match valid AND condition")
	require.Equal(t, m.Words, matched)

	isMatched, matched = m.MatchWords("b", nil)
	require.False(t, isMatched, "Could match invalid AND condition")
	require.Equal(t, []string{}, matched)
}

func TestORCondition(t *testing.T) {
	m := &Matcher{condition: ORCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b", nil)
	require.True(t, isMatched, "Could not match valid OR condition")
	require.Equal(t, []string{"a"}, matched)

	isMatched, matched = m.MatchWords("b", nil)
	require.True(t, isMatched, "Could not match valid OR condition")
	require.Equal(t, []string{"b"}, matched)

	isMatched, matched = m.MatchWords("c", nil)
	require.False(t, isMatched, "Could match invalid OR condition")
	require.Equal(t, []string{}, matched)
}

func TestHexEncoding(t *testing.T) {
	m := &Matcher{Encoding: "hex", Type: "word", Part: "body", Words: []string{"50494e47"}}
	err := m.CompileMatchers()
	require.Nil(t, err, "could not compile matcher")

	isMatched, matched := m.MatchWords("PING", nil)
	require.True(t, isMatched, "Could not match valid Hex condition")
	require.Equal(t, m.Words, matched)
}
