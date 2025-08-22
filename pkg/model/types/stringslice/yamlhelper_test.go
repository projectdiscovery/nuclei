package stringslice

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type testNormalizer struct {
	toLowerCase bool
}

func (t *testNormalizer) Normalize(value string) string {
	if t.toLowerCase {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return strings.TrimSpace(value)
}

func TestUnmarshalYAMLNode(t *testing.T) {
	tests := []struct {
		name        string
		yamlInput   string
		normalizer  StringNormalizer
		expected    []string
		expectError bool
	}{
		{
			name:      "scalar string",
			yamlInput: `"test"`,
			expected:  []string{"test"},
		},
		{
			name:       "scalar with spaces",
			yamlInput:  `"  test  "`,
			normalizer: &testNormalizer{toLowerCase: true},
			expected:   []string{"test"},
		},
		{
			name:      "comma separated string",
			yamlInput: `"one,two,three"`,
			expected:  []string{"one", "two", "three"},
		},
		{
			name:       "comma separated with normalization",
			yamlInput:  `"ONE, Two , THREE"`,
			normalizer: &testNormalizer{toLowerCase: true},
			expected:   []string{"one", "two", "three"},
		},
		{
			name:      "empty string",
			yamlInput: `""`,
			expected:  []string{},
		},
		{
			name:      "whitespace only",
			yamlInput: `"   "`,
			expected:  []string{},
		},
		{
			name:      "sequence of strings",
			yamlInput: `["one", "two", "three"]`,
			expected:  []string{"one", "two", "three"},
		},
		{
			name:       "sequence with normalization",
			yamlInput:  `[" ONE ", "Two", " THREE "]`,
			normalizer: &testNormalizer{toLowerCase: true},
			expected:   []string{"one", "two", "three"},
		},
		{
			name:      "mixed sequence",
			yamlInput: `["string", 123, true]`,
			expected:  []string{"string", "123", "true"},
		},
		{
			name:      "empty sequence",
			yamlInput: `[]`,
			expected:  []string{},
		},
		{
			name:      "single item sequence",
			yamlInput: `["single"]`,
			expected:  []string{"single"},
		},
		{
			name:        "unsupported mapping",
			yamlInput:   `{key: value}`,
			expectError: true,
		},
		{
			name:        "unsupported null",
			yamlInput:   `null`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node yaml.Node
			err := yaml.Unmarshal([]byte(tt.yamlInput), &node)
			require.NoError(t, err)

			result, err := UnmarshalYAMLNode(&node, tt.normalizer)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnmarshalYAMLNode_WithAlias(t *testing.T) {
	yamlInput := `
anchor: &test "value"
reference: *test
`
	var data map[string]yaml.Node
	err := yaml.Unmarshal([]byte(yamlInput), &data)
	require.NoError(t, err)

	referenceNode := data["reference"]
	result, err := UnmarshalYAMLNode(&referenceNode, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"value"}, result)
}

func TestStringSlice_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name      string
		yamlInput string
		expected  []string
	}{
		{
			name:      "string with case normalization",
			yamlInput: `"TEST, Value"`,
			expected:  []string{"test", "value"},
		},
		{
			name:      "sequence with case normalization",
			yamlInput: `["TEST", " Value "]`,
			expected:  []string{"test", "value"},
		},
		{
			name:      "empty input",
			yamlInput: `""`,
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ss StringSlice
			err := yaml.Unmarshal([]byte(tt.yamlInput), &ss)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ss.ToSlice())
		})
	}
}

func TestRawStringSlice_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name      string
		yamlInput string
		expected  []string
	}{
		{
			name:      "string without normalization",
			yamlInput: `"TEST, Value"`,
			expected:  []string{"TEST", " Value"},
		},
		{
			name:      "sequence without normalization",
			yamlInput: `["TEST", " Value "]`,
			expected:  []string{"TEST", " Value "},
		},
		{
			name:      "empty input",
			yamlInput: `""`,
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rss RawStringSlice
			err := yaml.Unmarshal([]byte(tt.yamlInput), &rss)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, rss.Value.([]string))
		})
	}
}

func TestUnmarshalYAMLNode_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *yaml.Node
		normalizer  StringNormalizer
		expected    []string
		expectError bool
	}{
		{
			name: "alias reference",
			setup: func() *yaml.Node {
				yamlInput := `
anchor: &test "value"
reference: *test
`
				var doc yaml.Node
				_ = yaml.Unmarshal([]byte(yamlInput), &doc)

				// Extract the reference node from the document
				mappingNode := doc.Content[0]
				for i := 0; i < len(mappingNode.Content); i += 2 {
					if mappingNode.Content[i].Value == "reference" {
						return mappingNode.Content[i+1]
					}
				}
				return nil
			},
			expected: []string{"value"},
		},
		{
			name: "comma in quotes",
			setup: func() *yaml.Node {
				var node yaml.Node
				_ = yaml.Unmarshal([]byte(`"value,with,commas"`), &node)
				return &node
			},
			expected: []string{"value", "with", "commas"},
		},
		{
			name: "sequence with mixed types",
			setup: func() *yaml.Node {
				var node yaml.Node
				_ = yaml.Unmarshal([]byte(`[1, true, "string", 3.14]`), &node)
				return &node
			},
			expected: []string{"1", "true", "string", "3.14"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.setup()
			result, err := UnmarshalYAMLNode(node, tt.normalizer)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkUnmarshalYAMLNode_String(b *testing.B) {
	yamlInput := `"one,two,three,four,five"`
	var node yaml.Node
	yaml.Unmarshal([]byte(yamlInput), &node)
	normalizer := &testNormalizer{toLowerCase: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalYAMLNode(&node, normalizer)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalYAMLNode_Sequence(b *testing.B) {
	yamlInput := `["one", "two", "three", "four", "five"]`
	var node yaml.Node
	yaml.Unmarshal([]byte(yamlInput), &node)
	normalizer := &testNormalizer{toLowerCase: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalYAMLNode(&node, normalizer)
		if err != nil {
			b.Fatal(err)
		}
	}
}
