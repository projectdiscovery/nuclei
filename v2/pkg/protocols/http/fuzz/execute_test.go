package fuzz

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleIsExecutable(t *testing.T) {
	rule := &Rule{Part: "query"}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	parsed, _ := url.Parse("https://example.com/?url=localhost")
	result := rule.isExecutable(parsed)
	require.True(t, result, "could not get correct result")

	parsed, _ = url.Parse("https://example.com/")
	result = rule.isExecutable(parsed)
	require.False(t, result, "could not get correct result")
}
