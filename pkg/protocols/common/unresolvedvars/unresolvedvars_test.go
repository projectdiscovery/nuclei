package unresolvedvars

import (
	"errors"
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/stretchr/testify/require"
)

func TestIs(t *testing.T) {
	require.True(t, Is(expressions.ContainsUnresolvedVariables("{{user}}")))
	require.True(t, Is(expressions.ContainsVariablesWithIgnoreList(nil, "{{user}}")))
	require.True(t, Is(fmt.Errorf("%w `%v` found in request", expressions.ErrUnresolvedVariables, "{{user}}")))
	require.True(t, Is(errkit.Wrap(expressions.ContainsUnresolvedVariables("{{user}}"), "could not build request")))
	// an unrelated error that only mentions the phrase is not a skip
	require.False(t, Is(errors.New("unresolved variables found: user")))
	require.False(t, Is(errors.New("connection refused")))
	require.False(t, Is(nil))
}
