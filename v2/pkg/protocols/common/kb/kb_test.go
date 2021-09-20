package kb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKBGetSet(t *testing.T) {
	kb := New()
	kb.Set("host", "test", "test-value")
	values := kb.Get("host", "test")
	require.Equal(t, []string{"test-value"}, values, "could not get set values")
}
