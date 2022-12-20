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
		{input: "{{a+{{c+d}}+b+{{e}}}}", expected: "aa1cc3dd4bb2ee5", extra: map[string]interface{}{"a": "aa1", "b": "bb2", "c": "cc3", "d": "dd4", "e": "ee5"}},
		{input: "{{a+{{c+d}}+b+{{e}}}}", expected: "{{a+cc3dd4+b+ee5}}", extra: map[string]interface{}{"c": "cc3", "d": "dd4", "e": "ee5"}},
	}
	for _, item := range items {
		value, err := Evaluate(item.input, item.extra)
		require.Nil(t, err, "could not evaluate helper")

		require.Equal(t, item.expected, value, "could not get correct expression")
	}
}
