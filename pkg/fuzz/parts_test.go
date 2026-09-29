package fuzz

import (
	"regexp"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func newFuzzTestInteractshClient(t *testing.T) *interactsh.Client {
	t.Helper()

	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           "oast.fun",
		CacheSize:           100,
		Eviction:            60 * time.Second,
		CooldownPeriod:      0,
		PollDuration:        5 * time.Second,
		DisableHttpFallback: true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func newFuzzTestVariables() variables.Variable {
	return variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
	}
}

func newFuzzGeneratorTestRule(t *testing.T, templateVars variables.Variable) *Rule {
	t.Helper()

	return &Rule{
		ruleType: replaceRuleType,
		options: &protocols.ExecutorOptions{
			Variables:  templateVars,
			Options:    &types.Options{},
			Interactsh: newFuzzTestInteractshClient(t),
		},
	}
}

func TestPrepareGeneratorValuesRendersDirectPayloadInteractshMarker(t *testing.T) {
	rule := newFuzzGeneratorTestRule(t, newFuzzTestVariables())

	values, urls := rule.prepareGeneratorValues(map[string]interface{}{
		"ssrf": "{{interactsh-url}}",
	}, nil)
	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{Values: values}, "", "original", "https://{{ssrf}}", urls)

	require.NoError(t, err)
	require.Len(t, urls, 1)
	require.Equal(t, "https://"+urls[0], got)
	require.NotContains(t, got, "{{interactsh-url}}")
}

func TestPrepareGeneratorValuesRendersHelperEncodedPayloadInteractshMarker(t *testing.T) {
	rule := newFuzzGeneratorTestRule(t, newFuzzTestVariables())

	values, urls := rule.prepareGeneratorValues(map[string]interface{}{
		"ssrf": "{{url_encode('{{interactsh-url}}')}}",
	}, nil)
	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{Values: values}, "", "original", "{{ssrf}}", urls)

	require.NoError(t, err)
	require.Len(t, urls, 1)
	require.Equal(t, urls[0], got)
	require.NotContains(t, got, "{{interactsh-url}}")
	require.NotContains(t, got, "%7B%7Binteractsh-url%7D%7D")
}

func TestPrepareGeneratorValuesRendersVariableIndirectPayloadInteractshMarker(t *testing.T) {
	templateVars := newFuzzTestVariables()
	templateVars.Set("marker", "{{interactsh-url}}")
	rule := newFuzzGeneratorTestRule(t, templateVars)

	values, urls := rule.prepareGeneratorValues(map[string]interface{}{
		"interaction": "|nslookup {{marker}}|curl {{marker}}",
	}, nil)
	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{Values: values}, "", "original", "{{interaction}}", urls)

	require.NoError(t, err)
	require.Len(t, urls, 1)
	require.Equal(t, "|nslookup "+urls[0]+"|curl "+urls[0], got)
	require.NotContains(t, got, "{{marker}}")
	require.NotContains(t, got, "{{interactsh-url}}")
}

func TestPrepareGeneratorValuesDoesNotAllocateRuntimeInteractshMarker(t *testing.T) {
	rule := newFuzzGeneratorTestRule(t, newFuzzTestVariables())

	values, urls := rule.prepareGeneratorValues(
		map[string]interface{}{
			"payload": "{{server_value}}",
		},
		map[string]interface{}{
			"server_value": "{{interactsh-url}}",
		},
	)
	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{Values: values}, "", "original", "{{payload}}", urls)

	require.NoError(t, err)
	require.Empty(t, urls)
	require.Equal(t, "{{interactsh-url}}", got)
}

func TestPrepareGeneratorValuesDoesNotRenderConstantOverride(t *testing.T) {
	rule := newFuzzGeneratorTestRule(t, newFuzzTestVariables())
	rule.options.Constants = map[string]interface{}{
		"payload": "{{interactsh-url}}",
	}

	values, urls := rule.prepareGeneratorValues(
		map[string]interface{}{
			"payload": "{{interactsh-url}}",
		},
		nil,
	)
	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{Values: values}, "", "original", "{{payload}}", urls)

	require.NoError(t, err)
	require.Empty(t, urls)
	require.Equal(t, "{{interactsh-url}}", got)
}

func TestMergeInteractURLsPreservesCallerURLs(t *testing.T) {
	got := mergeInteractURLs(
		[]string{"https://caller.example/a", "https://shared.example"},
		[]string{"https://generated.example/b", "https://shared.example"},
	)

	require.Equal(t, []string{
		"https://caller.example/a",
		"https://shared.example",
		"https://generated.example/b",
	}, got)
}

func TestExecuteEvaluateDoesNotReevaluateRenderedPayload(t *testing.T) {
	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
	}
	rule := &Rule{
		ruleType: replaceRuleType,
		options: &protocols.ExecutorOptions{
			Variables:  templateVars,
			Options:    &types.Options{},
			Interactsh: &interactsh.Client{},
		},
	}

	input := &ExecuteRuleInput{
		Values: map[string]interface{}{
			"server_value": "{{secret}}",
			"secret":       "leaked-secret",
		},
	}

	got, urls, err := rule.executeEvaluate(input, "", "original", "{{server_value}}", nil)

	require.NoError(t, err)
	require.Empty(t, urls)
	require.Equal(t, "{{secret}}", got)
}

func TestExecuteEvaluateReturnsRenderError(t *testing.T) {
	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
	}
	rule := &Rule{
		ruleType: replaceRuleType,
		options: &protocols.ExecutorOptions{
			Variables: templateVars,
			Options:   &types.Options{},
		},
	}

	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{}, "", "original", "{{md5(missing)}}", nil)

	require.Error(t, err)
	require.Empty(t, urls)
	require.Equal(t, "{{md5(missing)}}", got)
}

func TestExecuteEvaluateReplacesHelperEncodedTemplateInteractshMarker(t *testing.T) {
	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
	}
	rule := &Rule{
		ruleType: replaceRuleType,
		options: &protocols.ExecutorOptions{
			Variables:  templateVars,
			Options:    &types.Options{},
			Interactsh: newFuzzTestInteractshClient(t),
		},
	}

	got, urls, err := rule.executeEvaluate(&ExecuteRuleInput{}, "", "original", "{{url_encode('{{interactsh-url}}')}}", nil)

	require.NoError(t, err)
	require.Len(t, urls, 1)
	require.Equal(t, urls[0], got)
	require.NotContains(t, got, "{{interactsh-url}}")
	require.NotContains(t, got, "%7B%7Binteractsh-url%7D%7D")
}

func TestExecuteEvaluateDoesNotReplaceRuntimeInteractshMarkers(t *testing.T) {
	items := []struct {
		name  string
		value string
	}{
		{name: "raw marker", value: "{{interactsh-url}}"},
		{name: "url encoded marker", value: "%7B%7Binteractsh-url%7D%7D"},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			templateVars := variables.Variable{
				InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
			}
			rule := &Rule{
				ruleType: replaceRuleType,
				options: &protocols.ExecutorOptions{
					Variables:  templateVars,
					Options:    &types.Options{},
					Interactsh: newFuzzTestInteractshClient(t),
				},
			}
			input := &ExecuteRuleInput{
				Values: map[string]interface{}{
					"server_value": item.value,
				},
			}

			got, urls, err := rule.executeEvaluate(input, "", "original", "{{server_value}}", nil)

			require.NoError(t, err)
			require.Empty(t, urls)
			require.Equal(t, item.value, got)
		})
	}
}

func TestExecuteEvaluateUsesRenderedPayloadForAllRuleTypes(t *testing.T) {
	items := []struct {
		name         string
		ruleType     ruleType
		value        string
		replaceRegex string
		expected     string
	}{
		{name: "prefix", ruleType: prefixRuleType, value: "base", expected: "{{secret}}base"},
		{name: "postfix", ruleType: postfixRuleType, value: "base", expected: "base{{secret}}"},
		{name: "infix", ruleType: infixRuleType, value: "base", expected: "ba{{secret}}se"},
		{name: "replace", ruleType: replaceRuleType, value: "base", expected: "{{secret}}"},
		{name: "replace-regex", ruleType: replaceRegexRuleType, value: "base123", replaceRegex: `[0-9]+`, expected: "base{{secret}}"},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			templateVars := variables.Variable{
				InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
			}
			rule := &Rule{
				ruleType: item.ruleType,
				options: &protocols.ExecutorOptions{
					Variables:  templateVars,
					Options:    &types.Options{},
					Interactsh: &interactsh.Client{},
				},
			}
			if item.replaceRegex != "" {
				rule.replaceRegex = regexp.MustCompile(item.replaceRegex)
			}

			input := &ExecuteRuleInput{
				Values: map[string]interface{}{
					"server_value": "{{secret}}",
					"secret":       "leaked-secret",
				},
			}

			got, urls, err := rule.executeEvaluate(input, "", item.value, "{{server_value}}", nil)

			require.NoError(t, err)
			require.Empty(t, urls)
			require.Equal(t, item.expected, got)
		})
	}
}
