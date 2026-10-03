package unresolvedvars

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIs(t *testing.T) {
	require.True(t, Is(errors.New("unresolved variables found: user")))
	require.True(t, Is(errors.New("unresolved variables `{{user}}` found in request")))
	require.False(t, Is(errors.New("connection refused")))
	require.False(t, Is(nil))
}
