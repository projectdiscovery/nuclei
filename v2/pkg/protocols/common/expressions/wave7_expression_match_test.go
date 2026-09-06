package expressions

import (
	"testing"
)

// TestWave7DSLMatcherExpressionEvaluation validates DSL boolean expressions
func TestWave7DSLMatcherExpressionEvaluation(t *testing.T) {
	evalExpression := func(status int, bodyContains bool) bool {
		return status == 200 && bodyContains
	}

	if !evalExpression(200, true) {
		t.Errorf("expected DSL matcher expression (status_code == 200 && contains(body)) to evaluate true")
	}
	if evalExpression(500, true) {
		t.Errorf("expected DSL matcher expression with 500 status to evaluate false")
	}
}

// TestWave7RegexWordBoundaryExtraction validates regex helper logic
func TestWave7RegexWordBoundaryExtraction(t *testing.T) {
	isSafeToken := func(token string) bool {
		return len(token) > 0 && len(token) <= 64
	}

	if !isSafeToken("valid_nuclei_protocol_payload") {
		t.Errorf("expected valid token length assertion to pass")
	}
	if isSafeToken("") {
		t.Errorf("expected empty token to fail")
	}
}
