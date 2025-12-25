package variables

import (
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestVariablesEvaluate(t *testing.T) {
	data := `a2: "{{md5('test')}}"
a3: "this_is_random_text"
a4: "{{date_time('%Y-%M-%D')}}"
a5: "{{reverse(hostname)}}"
a6: "123456"`

	variables := Variable{}
	err := yaml.Unmarshal([]byte(data), &variables)
	require.NoError(t, err, "could not unmarshal variables")

	result := variables.Evaluate(map[string]interface{}{"hostname": "google.com"})
	a4 := time.Now().Format("2006-01-02")
	require.Equal(t, map[string]interface{}{"a2": "098f6bcd4621d373cade4e832627b4f6", "a3": "this_is_random_text", "a4": a4, "a5": "moc.elgoog", "a6": "123456"}, result, "could not get correct elements")

	// json
	data = `{
  "a2": "{{md5('test')}}",
  "a3": "this_is_random_text",
  "a4": "{{date_time('%Y-%M-%D')}}",
  "a5": "{{reverse(hostname)}}",
  "a6": "123456"
}`
	variables = Variable{}
	err = json.Unmarshal([]byte(data), &variables)
	require.NoError(t, err, "could not unmarshal json variables")

	result = variables.Evaluate(map[string]interface{}{"hostname": "google.com"})
	a4 = time.Now().Format("2006-01-02")
	require.Equal(t, map[string]interface{}{"a2": "098f6bcd4621d373cade4e832627b4f6", "a3": "this_is_random_text", "a4": a4, "a5": "moc.elgoog", "a6": "123456"}, result, "could not get correct elements")

}

func TestCheckForLazyEval(t *testing.T) {
	t.Run("undefined-parameters-in-expression", func(t *testing.T) {
		// Variables with expressions that reference undefined parameters
		// should be marked for lazy evaluation
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
		}
		variables.Set("var1", "{{sha1(serial)}}")           // 'serial' is undefined
		variables.Set("var2", "{{replace(user, '.', '')}}") // 'user' is undefined

		result := variables.checkForLazyEval()
		require.True(t, result, "should detect undefined parameters and set LazyEval=true")
		require.True(t, variables.LazyEval, "LazyEval flag should be true")
	})

	t.Run("self-referencing-variables", func(t *testing.T) {
		// Variables that reference other defined variables should NOT be lazy
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
		}
		variables.Set("base", "example")
		variables.Set("derived", "{{base}}_suffix") // 'base' is defined

		result := variables.checkForLazyEval()
		require.False(t, result, "should not set LazyEval for self-referencing defined variables")
		require.False(t, variables.LazyEval, "LazyEval flag should be false")
	})

	t.Run("constant-expressions", func(t *testing.T) {
		// Constant expressions without variables should NOT be lazy
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
		}
		variables.Set("const1", "{{2+2}}")
		variables.Set("const2", "{{rand_int(1, 100)}}")

		result := variables.checkForLazyEval()
		require.False(t, result, "should not set LazyEval for constant expressions")
		require.False(t, variables.LazyEval, "LazyEval flag should be false")
	})

	t.Run("known-runtime-variables", func(t *testing.T) {
		// Variables with known runtime variables (Host, BaseURL, etc.) should be lazy
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("url", "{{BaseURL}}/api")

		result := variables.checkForLazyEval()
		require.True(t, result, "should detect known runtime variables")
		require.True(t, variables.LazyEval, "LazyEval flag should be true")
	})

	t.Run("interactsh-url", func(t *testing.T) {
		// Variables with interactsh-url should be lazy
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("callback", "{{interactsh-url}}")

		result := variables.checkForLazyEval()
		require.True(t, result, "should detect interactsh-url")
		require.True(t, variables.LazyEval, "LazyEval flag should be true")
	})

	t.Run("mixed-defined-and-undefined", func(t *testing.T) {
		// Mix of defined and undefined parameters in actual expressions
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(3),
		}
		variables.Set("defined", "value")
		variables.Set("uses_defined", "{{base64(defined)}}")           // OK - 'defined' exists
		variables.Set("uses_undefined", "{{base64(undefined_param)}}") // NOT OK - 'undefined_param' doesn't exist

		result := variables.checkForLazyEval()
		require.True(t, result, "should detect undefined parameters even with some defined")
		require.True(t, variables.LazyEval, "LazyEval flag should be true")
	})

	t.Run("plain-strings-no-expressions", func(t *testing.T) {
		// Plain string values without expressions
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
		}
		variables.Set("plain1", "simple value")
		variables.Set("plain2", "another value")

		result := variables.checkForLazyEval()
		require.False(t, result, "should not set LazyEval for plain strings")
		require.False(t, variables.LazyEval, "LazyEval flag should be false")
	})

	t.Run("complex-expression-with-undefined", func(t *testing.T) {
		// Complex expression with multiple undefined parameters
		variables := &Variable{
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("complex", "{{sha1(cert_serial + issuer)}}")

		result := variables.checkForLazyEval()
		require.True(t, result, "should detect undefined parameters in complex expressions")
		require.True(t, variables.LazyEval, "LazyEval flag should be true")
	})
}

func TestVariablesEvaluateChained(t *testing.T) {
	t.Run("chained-variable-references", func(t *testing.T) {
		// Test that variables can reference previously defined variables
		// and that input values (like BaseURL) are available for evaluation
		// but not included in the result
		variables := &Variable{
			LazyEval:                  true, // skip auto-evaluation in UnmarshalYAML
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(3),
		}
		variables.Set("a", "hello")
		variables.Set("b", "{{a}} world")
		variables.Set("c", "{{b}}!")

		inputValues := map[string]interface{}{
			"BaseURL": "http://example.com",
			"Host":    "example.com",
		}

		result := variables.Evaluate(inputValues)

		// Result should contain only the defined variables, not input values
		require.Len(t, result, 3, "result should contain exactly 3 variables")
		require.NotContains(t, result, "BaseURL", "result should not contain input values")
		require.NotContains(t, result, "Host", "result should not contain input values")

		// Chained evaluation should work correctly
		require.Equal(t, "hello", result["a"])
		require.Equal(t, "hello world", result["b"])
		require.Equal(t, "hello world!", result["c"])
	})

	t.Run("variables-using-input-values", func(t *testing.T) {
		// Test that variables can use input values in expressions
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
		}
		variables.Set("api_url", "{{BaseURL}}/api/v1")
		variables.Set("full_path", "{{api_url}}/users")

		inputValues := map[string]interface{}{
			"BaseURL": "http://example.com",
		}

		result := variables.Evaluate(inputValues)

		require.Len(t, result, 2)
		require.Equal(t, "http://example.com/api/v1", result["api_url"])
		require.Equal(t, "http://example.com/api/v1/users", result["full_path"])
		require.NotContains(t, result, "BaseURL")
	})

	t.Run("mixed-expressions-and-chaining", func(t *testing.T) {
		// Test combining DSL functions with chained variables
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(3),
		}
		variables.Set("token", "secret123")
		variables.Set("hashed", "{{md5(token)}}")
		variables.Set("header", "X-Auth: {{hashed}}")

		result := variables.Evaluate(map[string]interface{}{})

		require.Equal(t, "secret123", result["token"])
		require.Equal(t, "5d7845ac6ee7cfffafc5fe5f35cf666d", result["hashed"]) // md5("secret123")
		require.Equal(t, "X-Auth: 5d7845ac6ee7cfffafc5fe5f35cf666d", result["header"])
	})

	t.Run("evaluation-order-preserved", func(t *testing.T) {
		// Test that evaluation follows insertion order
		// (important for variables that depend on previously defined ones)
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(4),
		}
		variables.Set("step1", "A")
		variables.Set("step2", "{{step1}}B")
		variables.Set("step3", "{{step2}}C")
		variables.Set("step4", "{{step3}}D")

		result := variables.Evaluate(map[string]interface{}{})

		require.Equal(t, "A", result["step1"])
		require.Equal(t, "AB", result["step2"])
		require.Equal(t, "ABC", result["step3"])
		require.Equal(t, "ABCD", result["step4"])
	})
}

func TestEvaluateWithInteractshOverrideOrder(t *testing.T) {
	// This test demonstrates a bug where interactsh URL replacement is wasted
	// when an input value exists for the same variable key.
	//
	// Bug scenario:
	// 1. Variable "callback" is defined with "{{interactsh-url}}"
	// 2. Input values contain "callback" with some other value
	// 3. The interactsh-url is replaced first (wasting an interactsh URL)
	// 4. Then immediately overwritten by the input value
	//
	// Expected behavior: Input override should be checked FIRST, then interactsh
	// replacement should happen on the final valueString.

	t.Run("interactsh-replacement-with-input-override", func(t *testing.T) {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("callback", "{{interactsh-url}}")

		// Input provides an override that also contains interactsh-url
		inputValues := map[string]interface{}{
			"callback": "https://custom.{{interactsh-url}}/path",
		}

		// Create a real interactsh client for testing
		client, err := interactsh.New(&interactsh.Options{
			ServerURL:           "oast.fun",
			CacheSize:           100,
			Eviction:            60 * time.Second,
			CooldownPeriod:      5 * time.Second,
			PollDuration:        5 * time.Second,
			DisableHttpFallback: true,
		})
		require.NoError(t, err, "could not create interactsh client")
		defer client.Close()

		result, urls := variables.EvaluateWithInteractsh(inputValues, client)

		// The input override contains interactsh-url, so it should be replaced
		// and we should have exactly 1 URL from the input override
		require.Len(t, urls, 1, "should have 1 interactsh URL from input override")

		// The result should use the input override (with interactsh replaced)
		require.Contains(t, result["callback"], "https://custom.", "should use input override pattern")
		require.Contains(t, result["callback"], "/path", "should use input override pattern")
		require.NotContains(t, result["callback"], "{{interactsh-url}}", "interactsh should be replaced")
	})

	t.Run("interactsh-replacement-without-input-override", func(t *testing.T) {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("callback", "{{interactsh-url}}")

		// No input override for "callback"
		inputValues := map[string]interface{}{
			"other_key": "other_value",
		}

		client, err := interactsh.New(&interactsh.Options{
			ServerURL:           "oast.fun",
			CacheSize:           100,
			Eviction:            60 * time.Second,
			CooldownPeriod:      5 * time.Second,
			PollDuration:        5 * time.Second,
			DisableHttpFallback: true,
		})
		require.NoError(t, err, "could not create interactsh client")
		defer client.Close()

		result, urls := variables.EvaluateWithInteractsh(inputValues, client)

		// Should have 1 URL from the variable definition
		require.Len(t, urls, 1, "should have 1 interactsh URL")

		// The result should be the replaced interactsh URL
		require.NotContains(t, result["callback"], "{{interactsh-url}}", "interactsh should be replaced")
		require.NotEmpty(t, result["callback"], "callback should have a value")
	})
}
