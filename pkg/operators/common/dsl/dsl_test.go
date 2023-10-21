package dsl

import (
	"fmt"
	"testing"

	"github.com/Knetic/govaluate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDslExpressions(t *testing.T) {
	dslExpressions := map[string]interface{}{
		`resolve("scanme.sh")`:        "128.199.158.128",
		`resolve("scanme.sh","a")`:    "128.199.158.128",
		`resolve("scanme.sh","6")`:    "2400:6180:0:d0::91:1001",
		`resolve("scanme.sh","aaaa")`: "2400:6180:0:d0::91:1001",
		`resolve("scanme.sh","soa")`:  "ns69.domaincontrol.com",
	}

	testDslExpressionScenarios(t, dslExpressions)
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

func testDslExpressionScenarios(t *testing.T, dslExpressions map[string]interface{}) {
	for dslExpression, expectedResult := range dslExpressions {
		t.Run(dslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, dslExpression)

			if expectedResult != nil {
				assert.Equal(t, expectedResult, actualResult)
			}

			fmt.Printf("%s: \t %v\n", dslExpression, actualResult)
		})
	}
}
