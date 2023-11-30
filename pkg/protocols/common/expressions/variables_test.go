package expressions

import (
	"fmt"
	"testing"

	elabel "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/errors/label"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/stretchr/testify/require"
)

func TestUnresolvedVariablesCheck(t *testing.T) {
	tests := []struct {
		data string
		err  error
	}{
		{"{{test}}", errorutil.NewWithTag(elabel.UnresolvedVariablesErrorLabel, "unresolved variables found: test")},
		{"{{test}}/{{another}}", errorutil.NewWithTag(elabel.UnresolvedVariablesErrorLabel, "unresolved variables found: test,another")},
		{"test", nil},
		{"%7b%7btest%7d%7d", errorutil.NewWithTag(elabel.UnresolvedVariablesErrorLabel, "unresolved variables found: test")},
		{"%7B%7Bfirst%2Asecond%7D%7D", errorutil.NewWithTag(elabel.UnresolvedVariablesErrorLabel, fmt.Sprint("unresolved variables found: first%2Asecond"))},
		{"{{7*7}}", nil},
		{"{{'a'+'b'}}", nil},
		{"{{'a'}}", nil},
	}
	for _, test := range tests {
		err := ContainsUnresolvedVariables(test.data)
		require.Equal(t, test.err, err, "could not get unresolved variables")
	}
}
