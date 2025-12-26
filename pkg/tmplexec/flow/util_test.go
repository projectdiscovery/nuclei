package flow

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/stretchr/testify/require"
)

func TestHasMatchersPanicRegression(t *testing.T) {
	// This test ensures that hasMatchers does not panic when passed a slice containing nil.
	// This was the source of a reported panic when a request had no local operators.

	require.NotPanics(t, func() {
		all := []*operators.Operators{nil}
		result := hasMatchers(all)
		require.False(t, result)
	}, "hasMatchers should not panic with nil element in slice")

	require.NotPanics(t, func() {
		all := []*operators.Operators{nil, {}}
		result := hasMatchers(all)
		require.False(t, result)
	}, "hasMatchers should not panic with mix of nil and empty operators")
}

func TestHasOperatorsPanicRegression(t *testing.T) {
	// Also ensure hasOperators is safe
	require.NotPanics(t, func() {
		all := []*operators.Operators{nil}
		result := hasOperators(all)
		require.False(t, result)
	}, "hasOperators should not panic with nil element in slice")
}
