package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestANDCondition(t *testing.T) {
	m := &Matcher{condition: ANDCondition, Words: []string{"a", "b"}}

	matched := m.matchWords("a b")
	require.True(t, matched, "Could not match valid AND condition")

	matched = m.matchWords("b")
	require.False(t, matched, "Could match invalid AND condition")
}

func TestORCondition(t *testing.T) {
	m := &Matcher{condition: ORCondition, Words: []string{"a", "b"}}

	matched := m.matchWords("a b")
	require.True(t, matched, "Could not match valid OR condition")

	matched = m.matchWords("b")
	require.True(t, matched, "Could not match valid OR condition")

	matched = m.matchWords("c")
	require.False(t, matched, "Could match invalid OR condition")
}
