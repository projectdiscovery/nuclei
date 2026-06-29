package variables

import (
	"testing"
	"time"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
)

func withVariableTestHelperFunction(t *testing.T, name string, fn govaluate.ExpressionFunction) {
	t.Helper()

	originalFn, hadFn := dsl.HelperFunctions[name]
	dsl.HelperFunctions[name] = fn
	t.Cleanup(func() {
		if hadFn {
			dsl.HelperFunctions[name] = originalFn
			return
		}
		delete(dsl.HelperFunctions, name)
	})
}

type variableTestURLSource struct {
	calls int
}

func (v *variableTestURLSource) NewURLWithData(string) (string, error) {
	v.calls++
	return "https://example.oast.fun", nil
}

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

func TestVariablesEvaluateDynamicOverrideValuesAreData(t *testing.T) {
	var waitForCalls int
	withVariableTestHelperFunction(t, "wait_for", func(args ...interface{}) (interface{}, error) {
		waitForCalls++
		return true, nil
	})

	items := []struct {
		name     string
		value    string
		values   map[string]interface{}
		expected string
	}{
		{
			name:     "environment marker remains data",
			value:    "{{HOME}}",
			values:   map[string]interface{}{"HOME": "/home/scanner"},
			expected: "{{HOME}}",
		},
		{
			name:     "helper marker remains data",
			value:    "{{wait_for(5)}}",
			values:   map[string]interface{}{},
			expected: "{{wait_for(5)}}",
		},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			variables := &Variable{
				LazyEval:                  true,
				InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
			}
			variables.Set("token", "declared-token")

			inputValues := map[string]interface{}{"token": item.value}
			for key, value := range item.values {
				inputValues[key] = value
			}

			result := variables.Evaluate(inputValues)
			require.Equal(t, item.expected, result["token"])
		})
	}

	require.Zero(t, waitForCalls, "dynamic override helpers must not execute")
}

func TestVariablesEvaluateMatchingDynamicHelperOverrideIsData(t *testing.T) {
	var waitForCalls int
	withVariableTestHelperFunction(t, "wait_for", func(args ...interface{}) (interface{}, error) {
		waitForCalls++
		return true, nil
	})

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("token", "{{wait_for(5)}}")

	result := variables.Evaluate(map[string]interface{}{
		"token": "{{wait_for(5)}}",
	})

	require.Equal(t, "{{wait_for(5)}}", result["token"])
	require.Zero(t, waitForCalls, "matching dynamic override helpers must not execute")
}

func TestVariablesEvaluateDataValueInsertedIntoVariableIsData(t *testing.T) {
	var waitForCalls int
	withVariableTestHelperFunction(t, "wait_for", func(args ...interface{}) (interface{}, error) {
		waitForCalls++
		return true, nil
	})

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("header", "Bearer {{extracted_token}}")

	result := variables.EvaluateScope(NewScope().AddData(map[string]interface{}{
		"extracted_token": "{{wait_for(5)}}",
	})).Values

	require.Equal(t, "Bearer {{wait_for(5)}}", result["header"])
	require.Zero(t, waitForCalls, "data inserted into template variables must not execute")
}

func TestVariablesEvaluateReevaluatesStoredDeclaredValue(t *testing.T) {
	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("auth_header", "Bearer {{extracted_token}}")

	result := variables.EvaluateScope(NewScope().AddTemplate(map[string]interface{}{
		"auth_header": "Bearer {{extracted_token}}",
	}).AddData(map[string]interface{}{
		"extracted_token": "secret123",
	})).Values

	require.Equal(t, "Bearer secret123", result["auth_header"])
}

func TestVariablesEvaluateReevaluatesStoredDeclaredHelperValue(t *testing.T) {
	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("cname_filtered", `{{trim_suffix(dns_cname,".vercel-dns.com")}}`)

	result := variables.EvaluateScope(NewScope().AddTemplate(map[string]interface{}{
		"cname_filtered": `{{trim_suffix(dns_cname,".vercel-dns.com")}}`,
	}).AddData(map[string]interface{}{
		"dns_cname": "cname.vercel-dns.com",
	})).Values

	require.Equal(t, "cname", result["cname_filtered"])
}

func TestVariablesEvaluateWithInteractshMatchingRuntimeOverrideIsData(t *testing.T) {
	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("callback", "{{interactsh-url}}")

	source := &variableTestURLSource{}
	evaluation := variables.EvaluateWithInteractshScope(NewScope().AddData(map[string]interface{}{
		"callback": "{{interactsh-url}}",
	}), source)
	result, urls := evaluation.Values, evaluation.InteractURLs

	require.Empty(t, urls)
	require.Zero(t, source.calls, "matching runtime override marker must not allocate interactsh URLs")
	require.Equal(t, "{{interactsh-url}}", result["callback"])
}

func TestVariablesEvaluateWithInteractshDynamicOverrideIsData(t *testing.T) {
	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("callback", "https://declared.{{interactsh-url}}/path")

	result, urls := variables.EvaluateWithInteractsh(map[string]interface{}{
		"callback": "https://dynamic.{{interactsh-url}}/path",
	}, nil)

	require.Empty(t, urls)
	require.Equal(t, "https://dynamic.{{interactsh-url}}/path", result["callback"])
}

func TestRenderVariableValueWithInteractshKeepsURLsOnRenderError(t *testing.T) {
	source := &variableTestURLSource{}

	result, urls := renderVariableValueWithInteractsh("{{interactsh-url}} {{md5(missing)}}", nil, source, nil)

	require.Equal(t, 1, source.calls)
	require.Len(t, urls, 1)
	require.Contains(t, result, "https://example.oast.fun")
	require.NotContains(t, result, "{{interactsh-url}}")
}

func TestVariablesEvaluatePreservesDynamicShadowingCompatibility(t *testing.T) {
	t.Run("login-token-replaces-declared-empty-token", func(t *testing.T) {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("token", "")

		result := variables.Evaluate(map[string]interface{}{
			"token": "server-issued-token",
		})

		require.Equal(t, "server-issued-token", result["token"])
	})

	t.Run("edited-filename-replaces-initial-generated-filename", func(t *testing.T) {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("image_filename", "initial-upload-name")

		initial := variables.Evaluate(map[string]interface{}{})
		require.Equal(t, "initial-upload-name", initial["image_filename"])

		afterExtraction := variables.Evaluate(map[string]interface{}{
			"image_filename": "server-edited-name-e1",
		})
		require.Equal(t, "server-edited-name-e1", afterExtraction["image_filename"])
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

	t.Run("input-override-is-data", func(t *testing.T) {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
		}
		variables.Set("callback", "{{interactsh-url}}")

		// Input provides an override that also contains interactsh-url.
		// Overrides are dynamic data, so the marker must not allocate an
		// interactsh URL or get evaluated as template source.
		inputValues := map[string]interface{}{
			"callback": "https://custom.{{interactsh-url}}/path",
		}

		source := &variableTestURLSource{}

		evaluation := variables.EvaluateWithInteractshScope(NewScope().AddData(inputValues), source)
		result, urls := evaluation.Values, evaluation.InteractURLs

		require.Empty(t, urls, "dynamic override marker should not allocate interactsh URLs")
		require.Zero(t, source.calls, "dynamic override marker should not allocate interactsh URLs")
		require.Equal(t, "https://custom.{{interactsh-url}}/path", result["callback"])
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

		source := &variableTestURLSource{}

		evaluation := variables.EvaluateWithInteractshScope(NewScope().AddData(inputValues), source)
		result, urls := evaluation.Values, evaluation.InteractURLs

		// Should have 1 URL from the variable definition
		require.Len(t, urls, 1, "should have 1 interactsh URL")
		require.Equal(t, 1, source.calls, "should allocate from template variable source")

		// The result should be the replaced interactsh URL
		require.NotContains(t, result["callback"], "{{interactsh-url}}", "interactsh should be replaced")
		require.NotEmpty(t, result["callback"], "callback should have a value")
	})
}
