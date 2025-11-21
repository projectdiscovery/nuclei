package variables

import (
	"testing"
	"time"

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
