package fuzz

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestExecWithInput_DoesNotUseNumericParameterIndexForFrequency(t *testing.T) {
	tracker := frequency.New(128, 1)
	defer tracker.Close()

	req, err := retryablehttp.NewRequest("GET", "https://example.com/users/55", nil)
	require.NoError(t, err)

	tracker.MarkParameter("2", req.String(), "tmpl-6398")

	callbackCalled := false
	rule := &Rule{options: &protocols.ExecutorOptions{TemplateID: "tmpl-6398", FuzzParamsFrequency: tracker}}
	input := &ExecuteRuleInput{Callback: func(_ GeneratedRequest) bool {
		callbackCalled = true
		return true
	}}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.True(t, callbackCalled, "numeric parameter index should not be used as frequency key")
}

func TestExecWithInput_SkipsWhenActualParameterIsFrequent(t *testing.T) {
	tracker := frequency.New(128, 1)
	defer tracker.Close()

	req, err := retryablehttp.NewRequest("GET", "https://example.com/users/55", nil)
	require.NoError(t, err)

	tracker.MarkParameter("55", req.String(), "tmpl-6398")

	callbackCalled := false
	rule := &Rule{options: &protocols.ExecutorOptions{TemplateID: "tmpl-6398", FuzzParamsFrequency: tracker}}
	input := &ExecuteRuleInput{Callback: func(_ GeneratedRequest) bool {
		callbackCalled = true
		return true
	}}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.False(t, callbackCalled, "frequent actual parameter should be skipped")
}
