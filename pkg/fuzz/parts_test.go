package fuzz

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestExecWithInput_DoesNotUseNumericParameterIndexForFrequency verifies that
// numeric parameter indices (like "2") are not used as frequency keys.
// Instead, the actual parameter value (like "55") should be used.
// This prevents cross-URL collisions when fuzzing numeric path segments.
// Fixes: https://github.com/projectdiscovery/nuclei/issues/6398
func TestExecWithInput_DoesNotUseNumericParameterIndexForFrequency(t *testing.T) {
	tracker := frequency.New(128, 1)
	defer tracker.Close()

	req, err := retryablehttp.NewRequest("GET", "https://example.com/users/55", nil)
	require.NoError(t, err)

	// Mark the index "2" as frequent (this would incorrectly match any path with a "2" index)
	tracker.MarkParameter("2", req.String(), "tmpl-6398")

	callbackCalled := false
	rule := &Rule{options: &protocols.ExecutorOptions{TemplateID: "tmpl-6398", FuzzParamsFrequency: tracker}}
	input := &ExecuteRuleInput{Callback: func(_ GeneratedRequest) bool {
		callbackCalled = true
		return true
	}}

	// parameter="2" (the index), parameterValue="55" (the actual value)
	// With the fix, actualParameter becomes "55" and frequency check uses "55"
	// Since "55" is NOT marked as frequent, the callback should be called
	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.True(t, callbackCalled, "callback should be called because actualParameter '55' is not marked as frequent")
}

// TestExecWithInput_SkipsWhenActualParameterIsFrequent verifies that
// when the actual parameter value is marked as frequent, fuzzing is skipped.
func TestExecWithInput_SkipsWhenActualParameterIsFrequent(t *testing.T) {
	tracker := frequency.New(128, 1)
	defer tracker.Close()

	req, err := retryablehttp.NewRequest("GET", "https://example.com/users/55", nil)
	require.NoError(t, err)

	// Mark the actual value "55" as frequent
	tracker.MarkParameter("55", req.String(), "tmpl-6398")

	callbackCalled := false
	rule := &Rule{options: &protocols.ExecutorOptions{TemplateID: "tmpl-6398", FuzzParamsFrequency: tracker}}
	input := &ExecuteRuleInput{Callback: func(_ GeneratedRequest) bool {
		callbackCalled = true
		return true
	}}

	// parameter="2" (the index), parameterValue="55" (the actual value)
	// actualParameter becomes "55" which IS marked as frequent
	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.False(t, callbackCalled, "callback should NOT be called because actualParameter '55' is marked as frequent")
}

// TestExecWithInput_NonNumericParameterUnaffected verifies that non-numeric
// parameters still use the parameter name for frequency checks.
func TestExecWithInput_NonNumericParameterUnaffected(t *testing.T) {
	tracker := frequency.New(128, 1)
	defer tracker.Close()

	req, err := retryablehttp.NewRequest("GET", "https://example.com/search?q=test", nil)
	require.NoError(t, err)

	// Mark the parameter "q" as frequent
	tracker.MarkParameter("q", req.String(), "tmpl-test")

	callbackCalled := false
	rule := &Rule{options: &protocols.ExecutorOptions{TemplateID: "tmpl-test", FuzzParamsFrequency: tracker}}
	input := &ExecuteRuleInput{Callback: func(_ GeneratedRequest) bool {
		callbackCalled = true
		return true
	}}

	// For non-numeric parameter "q", actualParameter remains "q"
	err = rule.execWithInput(input, req, nil, nil, "q", "test", "", "", "", "")
	require.NoError(t, err)
	require.False(t, callbackCalled, "callback should NOT be called because parameter 'q' is marked as frequent")
}
