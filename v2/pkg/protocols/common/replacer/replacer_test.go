package replacer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplacerReplace(t *testing.T) {
	replaced := Replace("{{test}} §hello§ {{data}}", map[string]interface{}{"test": "random", "hello": "world"})
	require.Equal(t, "random world {{data}}", replaced, "could not get correct replaced data")
}
