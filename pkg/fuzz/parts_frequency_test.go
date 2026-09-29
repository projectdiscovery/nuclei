package fuzz

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestExecWithInputDoesNotUseNumericParameterIndexForFrequency verifies frequency
// checks do not key on numeric path segment indexes.
func TestExecWithInputDoesNotUseNumericParameterIndexForFrequency(t *testing.T) {
	tracker := frequency.New(64, 1)
	defer tracker.Close()

	const target = "https://example.com/users/55"
	const templateID = "tmpl-frequency-check"

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	tracker.MarkParameter("2", req.String(), templateID)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:          templateID,
			FuzzParamsFrequency: tracker,
		},
	}
	input := &ExecuteRuleInput{
		Callback: func(GeneratedRequest) bool {
			called = true
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.True(t, called, "numeric path index should not be used as frequency key")
}

// TestExecWithInputSkipsWhenActualParameterIsFrequent verifies requests are
// skipped when the normalized parameter value is marked frequent.
func TestExecWithInputSkipsWhenActualParameterIsFrequent(t *testing.T) {
	tracker := frequency.New(64, 1)
	defer tracker.Close()

	const target = "https://example.com/users/55"
	const templateID = "tmpl-frequency-check"

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	tracker.MarkParameter("55", req.String(), templateID)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:          templateID,
			FuzzParamsFrequency: tracker,
		},
	}
	input := &ExecuteRuleInput{
		Callback: func(GeneratedRequest) bool {
			called = true
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.False(t, called, "frequent actual parameter should be skipped")
}
