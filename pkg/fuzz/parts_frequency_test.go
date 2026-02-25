package fuzz

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestExecWithInputUsesActualParameterForFrequency(t *testing.T) {
	tracker := frequency.New(64, 1)
	target := "https://example.com/users/123"
	templateID := "tmpl-frequency-check"
	tracker.MarkParameter("users", target, templateID)

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

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

	// Numeric path parts normalize to parameterValue for request metadata.
	// Frequency tracking must use the normalized value to avoid skipping errors.
	err = rule.execWithInput(input, req, nil, nil, "0", "users", "", "", "", "")
	require.NoError(t, err)
	require.False(t, called, "request should be skipped when normalized path parameter is frequent")
}

