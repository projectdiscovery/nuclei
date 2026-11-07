package replacer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplacerReplace(t *testing.T) {
	tests := []struct {
		name     string
		template string
		values   map[string]interface{}
		expected string
	}{
		{
			name:     "Invalid arguments",
			template: "",
			values:   nil,
			expected: "",
		},
		{
			name:     "Nested",
			template: "{{base64_encode('{{test}}')}}",
			values:   map[string]interface{}{"test": "random"},
			expected: "{{base64_encode('random')}}",
		},
		{
			name:     "Basic",
			template: "{{test}} §hello§ {{data}}",
			values:   map[string]interface{}{"test": "random", "hello": "world"},
			expected: "random world {{data}}",
		},
		{
			name:     "No template variables",
			template: "Nothing to replace",
			values:   map[string]interface{}{"test": "random", "hello": "world"},
			expected: "Nothing to replace",
		},
		{
			name:     "Nested variable",
			template: "{{§var1§}} and §{{var2}}§",
			values:   map[string]interface{}{"var1": "variable 1", "var2": "variable 2"},
			expected: "{{variable 1}} and §variable 2§",
		},
		{
			name:     "Space in variable name",
			template: "{{var 1}} has a space",
			values:   map[string]interface{}{"var 1": "variable 1"},
			expected: "variable 1 has a space",
		},
		{
			name:     "Escaped marker in template",
			template: "{{\\§var 1\\§}}",
			values:   map[string]interface{}{"\\§var 1\\§": "variable 1"},
			expected: "variable 1",
		},
		{
			name:     "Escaping no marker in template",
			template: "{{\\§var 1\\§}}",
			values:   map[string]interface{}{"var 1": "variable 1"},
			expected: "{{\\§var 1\\§}}",
		},
		{
			name:     "Empty variable name",
			template: "{{}} §§ no vars here",
			values:   map[string]interface{}{"var 1": "variable 1"},
			expected: "{{}} §§ no vars here",
		},
		{
			name:     "Multiple replacement",
			template: "{{var1}} and §var1§ and another {{var2}}",
			values:   map[string]interface{}{"var1": "first variable", "var2": "second variable"},
			expected: "first variable and first variable and another second variable",
		},
		{
			name:     "Extra braces around a placeholder",
			template: "${{{num}}*{{{num}}",
			values:   map[string]any{"num": "7"},
			expected: "${7*{7",
		},
		{
			name:     "Unknown general marker before a known one",
			template: "§unknown§var1§",
			values:   map[string]any{"var1": "variable 1"},
			expected: "§unknownvariable 1",
		},
		{
			name:     "Unclosed markers",
			template: "{{{{ §§ {{var1}",
			values:   map[string]any{"var1": "variable 1"},
			expected: "{{{{ §§ {{var1}",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, Replace(test.template, test.values))
		})
	}
}

func TestReplacerReplaceDoesNotRescanValues(t *testing.T) {
	t.Parallel()

	values := map[string]any{
		"secret":      "leaked",
		"token":       "leaked",
		"general":     "§secret§",
		"parenthesis": "{{secret}}",
		"prefix":      "§",
	}

	tests := []struct {
		name     string
		template string
		expected string
	}{
		{
			name:     "general marker inside a parenthesis value",
			template: "{{general}}",
			expected: "§secret§",
		},
		{
			name:     "parenthesis marker inside a general value",
			template: "§parenthesis§",
			expected: "{{secret}}",
		},
		{
			name:     "value completes a marker with the template text after it",
			template: "{{prefix}}token§",
			expected: "§token§",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.expected, Replace(test.template, values))
		})
	}
}

func TestReplacerReplaceOne(t *testing.T) {
	tests := []struct {
		name     string
		template string
		key      string
		value    interface{}
		expected string
	}{
		{
			name:     "Basic",
			template: "once upon a time there was a {{var1}}",
			key:      "var1",
			value:    "variable 1",
			expected: "once upon a time there was a variable 1",
		},
		{
			name:     "Basic Multiple Vars",
			template: "once upon a time there was a {{var1}} and a §var2§",
			key:      "var2",
			value:    "variable 2",
			expected: "once upon a time there was a {{var1}} and a variable 2",
		},
		{
			name:     "Missing key",
			template: "once upon a time there was a {{var1}}",
			key:      "",
			value:    "variable 1",
			expected: "once upon a time there was a {{var1}}",
		},
		{
			name:     "Replacement value empty",
			template: "{{var1}}nothing{{var1}} to{{var1}} see",
			key:      "var1",
			value:    "",
			expected: "nothing{{var1}} to{{var1}} see",
		},
		{
			name:     "Empty key and value different markers",
			template: "{{}}both§§ the{{}} 1st and 2nd markers are replaced",
			key:      "",
			value:    "",
			expected: "both the{{}} 1st and 2nd markers are replaced",
		},
		{
			name:     "Empty key and value same marker",
			template: "{{}}only{{}} the first marker is replaced{{}}",
			key:      "",
			value:    "",
			expected: "only{{}} the first marker is replaced{{}}",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, ReplaceOne(test.template, test.key, test.value))
		})
	}
}
