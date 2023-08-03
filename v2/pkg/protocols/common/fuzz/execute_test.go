package fuzz

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestRuleIsExecutable(t *testing.T) {
	rule := &Rule{Part: "query"}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	input := contextargs.NewWithInput("https://example.com/?url=localhost")
	result := rule.isExecutable(input)
	require.True(t, result, "could not get correct result")

	input = contextargs.NewWithInput("https://example.com/")
	result = rule.isExecutable(input)
	require.False(t, result, "could not get correct result")
}
