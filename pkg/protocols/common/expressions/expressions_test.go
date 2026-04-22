package expressions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluate(t *testing.T) {
	items := []struct {
		input    string
		expected string
		extra    map[string]interface{}
	}{
		{input: "{{url_encode('test}aaa')}}", expected: "test%7Daaa", extra: map[string]interface{}{}},
		{input: "{{hex_encode('PING')}}", expected: "50494e47", extra: map[string]interface{}{}},
		{input: "{{hex_encode('{{')}}", expected: "7b7b", extra: map[string]interface{}{}},
		{input: `{{concat("{{", 123, "*", 123, "}}")}}`, expected: "{{123*123}}", extra: map[string]interface{}{}},
		{input: `{{concat("{{", "123*123", "}}")}}`, expected: "{{123*123}}", extra: map[string]interface{}{}},
		{input: `{{"{{" + '123*123' + "}}"}}`, expected: `{{"{{" + '123*123' + "}}"}}`, extra: map[string]interface{}{}},
		{input: `{{a + '123*123' + b}}`, expected: `aa123*123bb`, extra: map[string]interface{}{"a": "aa", "b": "bb"}},
		{input: `{{concat(123,'*',123)}}`, expected: "123*123", extra: map[string]interface{}{}},
		{input: `{{1+1}}`, expected: "{{1+1}}", extra: map[string]interface{}{}},
		{input: `{{"1"+"1"}}`, expected: `{{"1"+"1"}}`, extra: map[string]interface{}{}},
		{input: `{{"1" + '*' + "1"}}`, expected: `{{"1" + '*' + "1"}}`, extra: map[string]interface{}{}},
		{input: `{{"a" + 'b' + "c"}}`, expected: `{{"a" + 'b' + "c"}}`, extra: map[string]interface{}{}},
		{input: `{{10*2}}`, expected: `{{10*2}}`, extra: map[string]interface{}{}},
		{input: `{{10/2}}`, expected: `{{10/2}}`, extra: map[string]interface{}{}},
		{input: `{{10-2}}`, expected: `{{10-2}}`, extra: map[string]interface{}{}},
		{input: "test", expected: "test", extra: map[string]interface{}{}},
		{input: "{{hex_encode(Item)}}", expected: "50494e47", extra: map[string]interface{}{"Item": "PING"}},
		{input: "{{hex_encode(Item)}}\r\n", expected: "50494e47\r\n", extra: map[string]interface{}{"Item": "PING"}},
		{input: "{{someTestData}}{{hex_encode('PING')}}", expected: "{{someTestData}}50494e47", extra: map[string]interface{}{}},
		{input: `_IWP_JSON_PREFIX_{{base64("{\"iwp_action\":\"add_site\",\"params\":{\"username\":\"\"}}")}}`, expected: "_IWP_JSON_PREFIX_eyJpd3BfYWN0aW9uIjoiYWRkX3NpdGUiLCJwYXJhbXMiOnsidXNlcm5hbWUiOiIifX0=", extra: map[string]interface{}{}},
		{input: "{{}}", expected: "{{}}", extra: map[string]interface{}{}},
		{input: `"{{hex_encode('PING')}}"`, expected: `"50494e47"`, extra: map[string]interface{}{}},
		// encoding functions must propagate unresolved markers instead of hiding them
		{input: "{{base64(rawhash)}}", expected: "{{contact_id}}{{email}}", extra: map[string]any{
			"rawhash": `{"contact_id":"{{contact_id}}","email":"{{email}}"}`,
		}},
	}
	for _, item := range items {
		value, err := Evaluate(item.input, item.extra)
		require.Nil(t, err, "could not evaluate helper")

		require.Equal(t, item.expected, value, "could not get correct expression")
	}
}

func TestEval(t *testing.T) {
	items := []struct {
		input    string
		values   map[string]interface{}
		expected interface{}
	}{
		{input: "'a' + 'a'", values: nil, expected: "aa"},
		{input: "10 + to_number(b)", values: map[string]interface{}{"b": "4"}, expected: float64(14)},
	}
	for _, item := range items {
		value, err := Eval(item.input, item.values)
		require.Nil(t, err, "could not evaluate helper")
		require.Equal(t, item.expected, value, "could not get correct expression")
	}
}

func TestEvaluateDoesNotReinterpretResolvedValues(t *testing.T) {
	items := []struct {
		name     string
		input    string
		expected string
		extra    map[string]interface{}
	}{
		{
			name:     "helper syntax in resolved values stays literal",
			input:    "/?x={{body}}",
			expected: `/?x={{md5("Hello")}}-by-Adelle`,
			extra: map[string]interface{}{
				"body": `{{md5("Hello")}}-by-Adelle`,
			},
		},
		{
			name:     "resolved values cannot access other variables",
			input:    "Authorization: {{body}}",
			expected: "Authorization: {{secret_token}}",
			extra: map[string]interface{}{
				"body":         "{{secret_token}}",
				"secret_token": "top-secret-cia-mi6-kgb-mossad-classified",
			},
		},
		{
			name:     "template-authored placeholders inside helper expressions still resolve",
			input:    "{{base64('{{Host}}')}}",
			expected: "MTI3LjAuMC4x",
			extra: map[string]interface{}{
				"Host": "127.0.0.1",
			},
		},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			value, err := Evaluate(item.input, item.extra)
			require.NoError(t, err)
			require.Equal(t, item.expected, value)
		})
	}
}

func TestEvaluateDoesNotExecuteHelpersFromResolvedValues(t *testing.T) {
	var calls int

	withTestHelperFunction(t, "test_side_effect", func(args ...interface{}) (interface{}, error) {
		calls++
		return "ok", nil
	})

	value, err := Evaluate("{{body}}", map[string]interface{}{
		"body": "{{test_side_effect(1)}}",
	})
	require.NoError(t, err)
	require.Equal(t, "{{test_side_effect(1)}}", value)
	require.Zero(t, calls)
}

func TestEvaluateReturnsErrorForInvalidTemplateExpression(t *testing.T) {
	_, err := Evaluate("{{base64()}}", map[string]interface{}{})
	require.Error(t, err)
	require.ErrorContains(t, err, `failed to evaluate expression "base64()"`)
}

func TestEvaluateErrorDoesNotLeakResolvedValues(t *testing.T) {
	_, err := Evaluate("{{base64('{{secret_token}}', 'extra')}}", map[string]interface{}{
		"secret_token": "top-secret-cia-mi6-kgb-mossad-classified",
	})
	require.Error(t, err)
	require.ErrorContains(t, err, `failed to evaluate expression "base64('{{secret_token}}', 'extra')"`)
	require.NotContains(t, err.Error(), "top-secret-cia-mi6-kgb-mossad-classified")
}

func TestEvaluatePlainExpressionsWithMarkerLikeValues(t *testing.T) {
	value, err := Evaluate("{{body != ''}}", map[string]interface{}{
		"body": "{{contact_id}}",
	})
	require.NoError(t, err)
	require.Equal(t, "true", value)
}

func TestEvaluatePreservesVisibleMarkersFromHelperResults(t *testing.T) {
	value, err := Evaluate("{{concat(body, '-x')}}", map[string]interface{}{
		"body": "{{contact_id}}",
	})
	require.NoError(t, err)
	require.Equal(t, "{{contact_id}}-x", value)
}
