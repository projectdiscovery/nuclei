package excludematchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExcludeMatchers(t *testing.T) {
	em := New([]string{"test-template:test-matcher", "new-template:*", "*:new-matcher", "only-template-id"})

	require.True(t, em.Match("test-template", "test-matcher"), "could not get template-matcher value")
	require.False(t, em.Match("test-template", "random-matcher"), "could get template-matcher value")

	require.True(t, em.Match("new-template", "random-matcher"), "could not get template-matcher value wildcard")
	require.True(t, em.Match("random-template", "new-matcher"), "could not get template-matcher value wildcard")

	require.True(t, em.Match("only-template-id", "test"), "could not get only template id match value")
}
