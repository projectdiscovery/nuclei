package dsl

import (
	"fmt"
	"testing"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDslExpressions(t *testing.T) {
	// Use Google DNS for more reliable testing
	googleDNS := []string{"8.8.8.8:53", "8.8.4.4:53"}

	dslExpressions := map[string]interface{}{
		`resolve("scanme.sh")`:        "128.199.158.128",
		`resolve("scanme.sh","a")`:    "128.199.158.128",
		`resolve("scanme.sh","6")`:    "2400:6180:0:d0::91:1001",
		`resolve("scanme.sh","aaaa")`: "2400:6180:0:d0::91:1001",
		`resolve("scanme.sh","soa")`:  "ns69.domaincontrol.com",
	}

	testDslExpressionScenariosWithDNS(t, dslExpressions, googleDNS)
}

func evaluateExpression(t *testing.T, dslExpression string) interface{} {
	compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, HelperFunctions)
	require.NoError(t, err, "Error while compiling the %q expression", dslExpression)

	actualResult, err := compiledExpression.Evaluate(make(map[string]interface{}))
	require.NoError(t, err, "Error while evaluating the compiled %q expression", dslExpression)

	for _, negativeTestWord := range []string{"panic", "invalid", "error"} {
		require.NotContains(t, fmt.Sprintf("%v", actualResult), negativeTestWord)
	}

	return actualResult
}

func testDslExpressionScenariosWithDNS(t *testing.T, dslExpressions map[string]interface{}, resolvers []string) {
	// Initialize DNS client pool with custom resolvers for testing
	err := dnsclientpool.Init(&types.Options{
		InternalResolversList: resolvers,
	})
	require.NoError(t, err, "Failed to initialize DNS client pool with custom resolvers")

	for dslExpression, expectedResult := range dslExpressions {
		t.Run(dslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, dslExpression)

			if expectedResult != nil {
				require.Equal(t, expectedResult, actualResult)
			}

			fmt.Printf("%s: \t %v\n", dslExpression, actualResult)
		})
	}
}
