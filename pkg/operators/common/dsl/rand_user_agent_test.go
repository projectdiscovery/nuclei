package dsl

import (
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/stretchr/testify/require"
)

// TestRandUserAgentIsNotCached guards the cacheable=false registration: a
// cached helper would hand back one frozen user agent for the whole run.
func TestRandUserAgentIsNotCached(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("rand_user_agent()", HelperFunctions)
	require.NoError(t, err, "could not compile rand_user_agent()")

	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		result, err := compiled.Evaluate(make(map[string]interface{}))
		require.NoError(t, err, "could not evaluate rand_user_agent()")
		require.NotEmpty(t, result, "rand_user_agent() returned an empty user agent")
		seen[result.(string)] = struct{}{}
	}

	require.Greater(t, len(seen), 1, "rand_user_agent() returned a cached value")
}

func TestRandUserAgentRejectsArguments(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(`rand_user_agent("chrome")`, HelperFunctions)
	require.NoError(t, err, "could not compile rand_user_agent() with an argument")

	_, err = compiled.Evaluate(make(map[string]interface{}))
	require.Error(t, err, "rand_user_agent() should reject arguments")
}
