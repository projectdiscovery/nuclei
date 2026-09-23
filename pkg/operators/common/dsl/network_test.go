package dsl

import (
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNetworkHelpersRequireScanContext(t *testing.T) {
	for _, source := range []string{`resolve("fixture.example")`, `jarm("127.0.0.1:443")`, `public_ip()`, `publicip()`} {
		t.Run(source, func(t *testing.T) {
			expression, err := govaluate.NewEvaluableExpressionWithFunctions(source, HelperFunctions)
			require.NoError(t, err)
			_, err = expression.Evaluate(nil)
			require.ErrorIs(t, err, ErrNetworkHelpersDisabled)
			require.ErrorContains(t, err, "scan context")
			_, err = EvalWithOptions(expression, nil, nil)
			require.ErrorIs(t, err, ErrNetworkHelpersDisabled)
		})
	}
}

func TestHasNetworkHelperIgnoresSubstringsAndQuotedCalls(t *testing.T) {
	for _, item := range []struct {
		source string
		want   bool
	}{
		{source: `resolve("fixture.example")`, want: true},
		{source: `public_ip()`, want: true},
		{source: `publicip()`, want: true},
		{source: `jarm("127.0.0.1:443")`, want: true},
		{source: `contains(body, "unresolved")`, want: false},
		{source: `contains(body, "resolve(")`, want: false},
		{source: `contains(body, "jarm(")`, want: false},
		{source: `contains(body, "public_ip(")`, want: false},
		{source: `len("publicip")`, want: false},
	} {
		t.Run(item.source, func(t *testing.T) {
			require.Equal(t, item.want, hasNetworkHelper(item.source))
			expression, err := govaluate.NewEvaluableExpressionWithFunctions(item.source, HelperFunctions)
			require.NoError(t, err)
			if item.want {
				return
			}
			result, err := EvalWithOptions(expression, map[string]interface{}{"body": "unresolved resolve( jarm( public_ip("}, &types.Options{ExecutionId: t.Name()})
			require.NoError(t, err)
			if item.source == `len("publicip")` {
				require.Equal(t, float64(8), result)
				return
			}
			require.Equal(t, true, result)
		})
	}
}
