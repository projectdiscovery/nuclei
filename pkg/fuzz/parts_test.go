package fuzz

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestExecWithInput_UsesActualParameterForFrequencyCheck(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/user/55/profile", nil)
	require.NoError(t, err)

	tracker := frequency.New(64, 1)
	t.Cleanup(tracker.Close)

	// Simulate prior frequency mark on numeric index key (old buggy behavior target).
	tracker.MarkParameter("2", req.String(), "tpl")

	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:           "tpl",
			FuzzParamsFrequency:  tracker,
		},
	}

	called := false
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			require.Equal(t, "55", gr.Parameter)
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.True(t, called, "callback should execute because actual parameter '55' is not marked frequent")
}

func TestExecWithInput_SkipsWhenActualParameterIsFrequent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/user/55/profile", nil)
	require.NoError(t, err)

	tracker := frequency.New(64, 1)
	t.Cleanup(tracker.Close)

	// Mark actual path segment value as frequent.
	tracker.MarkParameter("55", req.String(), "tpl")

	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:          "tpl",
			FuzzParamsFrequency: tracker,
		},
	}

	called := false
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.False(t, called, "callback should be skipped when actual parameter is frequent")
}
