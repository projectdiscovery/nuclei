package dsl

import (
	"testing"

	"github.com/projectdiscovery/govaluate"
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
