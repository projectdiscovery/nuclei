package expressions

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnresolvedVariablesCheck(t *testing.T) {
	tests := []struct {
		data string
		err  error
	}{
		{"{{test}}", errors.New("unresolved variables found: test")},
		{"{{test}}/{{another}}", errors.New("unresolved variables found: test,another")},
		{"test", nil},
		{"%7b%7btest%7d%7d", errors.New("unresolved variables found: test")},
	}
	for _, test := range tests {
		err := ContainsUnresolvedVariables(test.data)
		require.Equal(t, test.err, err, "could not get unresolved variables")
	}
}
