package fuzz

import (
	"github.com/projectdiscovery/retryablehttp-go"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleIsExecutable(t *testing.T) {
	rule := &Rule{Part: "query"}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	req, err := retryablehttp.NewRequest("GET", "https://example.com/?url=localhost", nil)
	require.NoError(t, err, "could not build request")

	result := rule.isExecutable(req)
	require.True(t, result, "could not get correct result")

	req, err = retryablehttp.NewRequest("GET", "https://example.com/", nil)
	require.NoError(t, err, "could not build request")

	result = rule.isExecutable(req)
	require.False(t, result, "could not get correct result")
}
