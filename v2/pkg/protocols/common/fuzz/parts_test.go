package fuzz

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/stretchr/testify/require"
)

func TestExecuteQueryPartRule(t *testing.T) {
	URL := "http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile"
	options := &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}
	t.Run("single", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: queryPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedURL []string
		input := contextargs.NewWithInput(URL)
		err := rule.executeQueryPartRule(&ExecuteRuleInput{
			Input: input,
			Callback: func(gr GeneratedRequest) bool {
				generatedURL = append(generatedURL, gr.Request.URL.String())
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.ElementsMatch(t, []string{
			"http://localhost:8080/?url=localhost1337'&mode=multiple&file=passwdfile",
			"http://localhost:8080/?url=localhost&mode=multiple1337'&file=passwdfile",
			"http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile1337'",
		}, generatedURL, "could not get generated url")
	})
	t.Run("multiple", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: queryPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedURL string
		input := contextargs.NewWithInput(URL)
		err := rule.executeQueryPartRule(&ExecuteRuleInput{
			Input: input,
			Callback: func(gr GeneratedRequest) bool {
				generatedURL = gr.Request.URL.String()
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.Equal(t, "http://localhost:8080/?url=localhost1337'&mode=multiple1337'&file=passwdfile1337'", generatedURL, "could not get generated url")
	})
}

func TestExecuteReplaceRule(t *testing.T) {
	tests := []struct {
		ruleType    ruleType
		value       string
		replacement string
		expected    string
	}{
		{replaceRuleType, "test", "replacement", "replacement"},
		{prefixRuleType, "test", "prefix", "prefixtest"},
		{postfixRuleType, "test", "postfix", "testpostfix"},
		{infixRuleType, "", "infix", "infix"},
		{infixRuleType, "0", "infix", "0infix"},
		{infixRuleType, "test", "infix", "teinfixst"},
	}
	for _, test := range tests {
		rule := &Rule{ruleType: test.ruleType}
		returned := rule.executeReplaceRule(nil, test.value, test.replacement)
		require.Equal(t, test.expected, returned, "could not get correct value")
	}
}
