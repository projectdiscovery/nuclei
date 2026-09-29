package fuzz

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestRuleMatchKeyOrValue(t *testing.T) {
	rule := &Rule{
		Part: "query",
	}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	result := rule.matchKeyOrValue("url", "")
	require.True(t, result, "could not get correct result")

	t.Run("key", func(t *testing.T) {
		rule := &Rule{Keys: []string{"url"}, Part: "query"}
		err := rule.Compile(nil, nil)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("url", "")
		require.True(t, result, "could not get correct result")
		result = rule.matchKeyOrValue("test", "")
		require.False(t, result, "could not get correct result")
	})
	t.Run("value", func(t *testing.T) {
		rule := &Rule{ValuesRegex: []string{`https?:\/\/?([-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b)*(\/[\/\d\w\.-]*)*(?:[\?])*(.+)*`}, Part: "query"}
		err := rule.Compile(nil, nil)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("", "http://localhost:80")
		require.True(t, result, "could not get correct result")
		result = rule.matchKeyOrValue("test", "random")
		require.False(t, result, "could not get correct result")
	})
}

func TestEvaluateVariables(t *testing.T) {
	t.Run("keys", func(t *testing.T) {
		rule := &Rule{
			Keys: []string{"{{foo_var}}"},
			Part: "query",
		}

		// mock
		templateVars := variables.Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		templateVars.Set("foo_var", "foo_var_value")

		constants := map[string]interface{}{
			"const_key": "const_value",
		}

		options := &types.Options{}

		// runtime vars (to simulate CLI)
		runtimeVars := goflags.RuntimeMap{}
		_ = runtimeVars.Set("runtime_key=runtime_value")
		options.Vars = runtimeVars

		executorOpts := &protocols.ExecutorOptions{
			Variables: templateVars,
			Constants: constants,
			Options:   options,
		}

		err := rule.Compile(nil, executorOpts)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("foo_var_value", "test_value")
		require.True(t, result, "should match evaluated variable key")

		result = rule.matchKeyOrValue("{{foo_var}}", "test_value")
		require.False(t, result, "should not match unevaluated variable key")
	})

	t.Run("keys-regex", func(t *testing.T) {
		rule := &Rule{
			KeysRegex: []string{"^{{foo_var}}"},
			Part:      "query",
		}

		templateVars := variables.Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		templateVars.Set("foo_var", "foo_var_value")

		executorOpts := &protocols.ExecutorOptions{
			Variables: templateVars,
			Constants: map[string]interface{}{},
			Options:   &types.Options{},
		}

		err := rule.Compile(nil, executorOpts)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("foo_var_value", "test_value")
		require.True(t, result, "should match evaluated variable in regex")

		result = rule.matchKeyOrValue("other_key", "test_value")
		require.False(t, result, "should not match non-matching key")
	})

	t.Run("values-regex", func(t *testing.T) {
		rule := &Rule{
			ValuesRegex: []string{"{{foo_var}}"},
			Part:        "query",
		}

		templateVars := variables.Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		templateVars.Set("foo_var", "test_pattern")

		executorOpts := &protocols.ExecutorOptions{
			Variables: templateVars,
			Constants: map[string]interface{}{},
			Options:   &types.Options{},
		}

		err := rule.Compile(nil, executorOpts)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("test_key", "test_pattern")
		require.True(t, result, "should match evaluated variable in values regex")

		result = rule.matchKeyOrValue("test_key", "other_value")
		require.False(t, result, "should not match non-matching value")
	})

	// complex vars w/ consts and runtime vars
	t.Run("complex-variables", func(t *testing.T) {
		rule := &Rule{
			Keys: []string{"{{template_var}}", "{{const_key}}", "{{runtime_key}}"},
			Part: "query",
		}

		templateVars := variables.Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		templateVars.Set("template_var", "template_value")

		constants := map[string]interface{}{
			"const_key": "const_value",
		}

		options := &types.Options{}
		runtimeVars := goflags.RuntimeMap{}
		_ = runtimeVars.Set("runtime_key=runtime_value")
		options.Vars = runtimeVars

		executorOpts := &protocols.ExecutorOptions{
			Variables: templateVars,
			Constants: constants,
			Options:   options,
		}

		err := rule.Compile(nil, executorOpts)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("template_value", "test")
		require.True(t, result, "should match template variable")

		result = rule.matchKeyOrValue("const_value", "test")
		require.True(t, result, "should match constant")

		result = rule.matchKeyOrValue("runtime_value", "test")
		require.True(t, result, "should match runtime variable")

		result = rule.matchKeyOrValue("{{template_var}}", "test")
		require.False(t, result, "should not match unevaluated template variable")
	})

	t.Run("invalid-variables", func(t *testing.T) {
		rule := &Rule{
			Keys: []string{"{{nonexistent_var}}"},
			Part: "query",
		}

		executorOpts := &protocols.ExecutorOptions{
			Variables: variables.Variable{
				InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
			},
			Constants: map[string]interface{}{},
			Options:   &types.Options{},
		}

		err := rule.Compile(nil, executorOpts)
		if err != nil {
			require.Contains(t, err.Error(), "unresolved", "error should mention unresolved variables")
		} else {
			result := rule.matchKeyOrValue("some_key", "some_value")
			require.False(t, result, "should not match when variables are unresolved")
		}
	})

	t.Run("evaluateVars-function", func(t *testing.T) {
		rule := &Rule{}

		templateVars := variables.Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		templateVars.Set("test_var", "test_value")

		constants := map[string]interface{}{
			"const_var": "const_value",
		}

		options := &types.Options{}
		runtimeVars := goflags.RuntimeMap{}
		_ = runtimeVars.Set("runtime_var=runtime_value")
		options.Vars = runtimeVars

		executorOpts := &protocols.ExecutorOptions{
			Variables: templateVars,
			Constants: constants,
			Options:   options,
		}

		rule.options = executorOpts

		// Test simple var substitution
		result, err := rule.evaluateVars("{{test_var}}")
		require.NoError(t, err, "should evaluate template variable")
		require.Equal(t, "test_value", result, "should return evaluated value")

		// Test constant substitution
		result, err = rule.evaluateVars("{{const_var}}")
		require.NoError(t, err, "should evaluate constant")
		require.Equal(t, "const_value", result, "should return constant value")

		// Test runtime var substitution
		result, err = rule.evaluateVars("{{runtime_var}}")
		require.NoError(t, err, "should evaluate runtime variable")
		require.Equal(t, "runtime_value", result, "should return runtime value")

		// Test mixed content
		result, err = rule.evaluateVars("prefix-{{test_var}}-suffix")
		require.NoError(t, err, "should evaluate mixed content")
		require.Equal(t, "prefix-test_value-suffix", result, "should return mixed evaluated content")

		// Test unresolved var - should either fail during evaluation or return original string
		result2, err := rule.evaluateVars("{{nonexistent}}")
		if err != nil {
			require.Contains(t, err.Error(), "unresolved", "should fail for unresolved variable")
		} else {
			// If no error, it should return the original unresolved variable
			require.Equal(t, "{{nonexistent}}", result2, "should return original string for unresolved variable")
		}
	})
}
