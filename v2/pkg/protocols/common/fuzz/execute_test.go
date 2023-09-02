package fuzz

import (
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func buildRequestFromUrl(url string) (*retryablehttp.Request, error) {
	parsed, err := urlutil.Parse(url)
	if err != nil {
		return nil, err
	}
	return retryablehttp.NewRequestFromURL("GET", parsed, nil)
}

func TestRuleIsExecutable(t *testing.T) {
	rule := &Rule{Part: "query"}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	req, err := buildRequestFromUrl("https://example.com/?url=localhost")
	require.NoError(t, err, "could not build request")

	result := rule.isExecutable(req)
	require.True(t, result, "could not get correct result")

	req, err = buildRequestFromUrl("https://example.com/")
	require.NoError(t, err, "could not build request")

	result = rule.isExecutable(req)
	require.False(t, result, "could not get correct result")
}
