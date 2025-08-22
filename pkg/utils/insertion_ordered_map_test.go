package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInsertionOrderedStringMap_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name           string
		yamlInput      string
		expectedKeys   []string
		expectedValues map[string]interface{}
		expectError    bool
	}{
		{
			name: "simple key-value pairs",
			yamlInput: `a1: test
a2: value
a3: new`,
			expectedKeys:   []string{"a1", "a2", "a3"},
			expectedValues: map[string]interface{}{"a1": "test", "a2": "value", "a3": "new"},
		},
		{
			name: "mixed data types",
			yamlInput: `string_key: hello
int_key: 42
float_key: 3.14
bool_key: true
null_key: null`,
			expectedKeys: []string{"string_key", "int_key", "float_key", "bool_key", "null_key"},
			expectedValues: map[string]interface{}{
				"string_key": "hello",
				"int_key":    "42",
				"float_key":  "3.14",
				"bool_key":   "true",
				"null_key":   "",
			},
		},
		{
			name:           "empty map",
			yamlInput:      `{}`,
			expectedKeys:   nil,
			expectedValues: map[string]interface{}{},
		},
		{
			name:           "single key-value",
			yamlInput:      `single: value`,
			expectedKeys:   []string{"single"},
			expectedValues: map[string]interface{}{"single": "value"},
		},
		{
			name: "complex values",
			yamlInput: `list_key: [1, 2, 3]
nested_key:
  inner: value`,
			expectedKeys: []string{"list_key", "nested_key"},
			expectedValues: map[string]interface{}{
				"list_key":   []interface{}{1, 2, 3},
				"nested_key": "map[inner:value]",
			},
		},
		{
			name: "special characters in keys",
			yamlInput: `"key-with-dash": value1
"key_with_underscore": value2
"key.with.dots": value3`,
			expectedKeys: []string{"key-with-dash", "key_with_underscore", "key.with.dots"},
			expectedValues: map[string]interface{}{
				"key-with-dash":       "value1",
				"key_with_underscore": "value2",
				"key.with.dots":       "value3",
			},
		},
		{
			name: "duplicate keys - last wins",
			yamlInput: `key: first
key: second`,
			expectedKeys:   []string{"key"},
			expectedValues: map[string]interface{}{"key": "second"},
		},
		{
			name:        "invalid YAML - not a mapping",
			yamlInput:   `- item1\n- item2`,
			expectError: true,
		},
		{
			name:        "invalid YAML - scalar value",
			yamlInput:   `just a string`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iosm InsertionOrderedStringMap
			err := yaml.Unmarshal([]byte(tt.yamlInput), &iosm)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Check length
			assert.Equal(t, len(tt.expectedKeys), iosm.Len())

			// Check key order
			var actualKeys []string
			iosm.ForEach(func(key string, value interface{}) {
				actualKeys = append(actualKeys, key)
			})
			if tt.expectedKeys == nil {
				assert.Empty(t, actualKeys)
			} else {
				assert.Equal(t, tt.expectedKeys, actualKeys)
			}

			// Check values
			iosm.ForEach(func(key string, value interface{}) {
				expected, exists := tt.expectedValues[key]
				assert.True(t, exists, "Key %s should exist in expected values", key)
				assert.Equal(t, expected, value, "Value for key %s should match", key)
			})
		})
	}
}

func TestInsertionOrderedStringMap_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name           string
		jsonInput      string
		expectedKeys   []string
		expectedValues map[string]interface{}
		expectError    bool
	}{
		{
			name:           "simple JSON object",
			jsonInput:      `{"b": "second", "a": "first", "c": "third"}`,
			expectedKeys:   []string{"b", "a", "c"}, // JSON doesn't preserve order, so we get map iteration order
			expectedValues: map[string]interface{}{"a": "first", "b": "second", "c": "third"},
		},
		{
			name:      "mixed types JSON",
			jsonInput: `{"string": "hello", "number": 42, "boolean": true, "null": null}`,
			expectedValues: map[string]interface{}{
				"string":  "hello",
				"number":  "42",
				"boolean": "true",
				"null":    "",
			},
		},
		{
			name:           "empty JSON object",
			jsonInput:      `{}`,
			expectedKeys:   []string{},
			expectedValues: map[string]interface{}{},
		},
		{
			name:        "invalid JSON",
			jsonInput:   `{"invalid": json}`,
			expectError: true,
		},
		{
			name:        "JSON array instead of object",
			jsonInput:   `["array", "values"]`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iosm InsertionOrderedStringMap
			err := json.Unmarshal([]byte(tt.jsonInput), &iosm)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, len(tt.expectedValues), iosm.Len())

			iosm.ForEach(func(key string, value interface{}) {
				expected, exists := tt.expectedValues[key]
				assert.True(t, exists, "Key %s should exist in expected values", key)
				assert.Equal(t, expected, value, "Value for key %s should match", key)
			})
		})
	}
}

func TestInsertionOrderedStringMap_Set(t *testing.T) {
	tests := []struct {
		name           string
		operations     []struct{ key, value string }
		expectedKeys   []string
		expectedValues map[string]interface{}
	}{
		{
			name: "sequential sets",
			operations: []struct{ key, value string }{
				{"first", "1"},
				{"second", "2"},
				{"third", "3"},
			},
			expectedKeys:   []string{"first", "second", "third"},
			expectedValues: map[string]interface{}{"first": "1", "second": "2", "third": "3"},
		},
		{
			name: "overwrite existing key",
			operations: []struct{ key, value string }{
				{"key1", "original"},
				{"key2", "value2"},
				{"key1", "updated"},
			},
			expectedKeys:   []string{"key1", "key2"},
			expectedValues: map[string]interface{}{"key1": "updated", "key2": "value2"},
		},
		{
			name: "empty key",
			operations: []struct{ key, value string }{
				{"", "empty_key_value"},
				{"normal", "normal_value"},
			},
			expectedKeys:   []string{"", "normal"},
			expectedValues: map[string]interface{}{"": "empty_key_value", "normal": "normal_value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iosm := NewEmptyInsertionOrderedStringMap(10)

			for _, op := range tt.operations {
				iosm.Set(op.key, op.value)
			}

			assert.Equal(t, len(tt.expectedKeys), iosm.Len())

			var actualKeys []string
			iosm.ForEach(func(key string, value interface{}) {
				actualKeys = append(actualKeys, key)
			})
			assert.Equal(t, tt.expectedKeys, actualKeys)

			iosm.ForEach(func(key string, value interface{}) {
				expected := tt.expectedValues[key]
				assert.Equal(t, expected, value)
			})
		})
	}
}

func TestInsertionOrderedStringMap_toString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"int", 42, "42"},
		{"int32", int32(42), "42"},
		{"int64", int64(42), "42"},
		{"float32", float32(3.14), "3.14"},
		{"float64", 3.14159, "3.14159"},
		{"uint", uint(42), "42"},
		{"uint64", uint64(42), "42"},
		{"byte slice", []byte("hello"), "hello"},
		{"interface slice", []interface{}{1, 2, 3}, []interface{}{1, 2, 3}},
		{"complex type", map[string]int{"a": 1}, "map[a:1]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInsertionOrderedStringMap_NewEmptyInsertionOrderedStringMap(t *testing.T) {
	sizes := []int{0, 1, 10, 100}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			iosm := NewEmptyInsertionOrderedStringMap(size)
			assert.NotNil(t, iosm)
			assert.Equal(t, 0, iosm.Len())
			assert.Equal(t, size, cap(iosm.keys))
			assert.Equal(t, 0, len(iosm.values))
		})
	}
}

func TestInsertionOrderedStringMap_NewInsertionOrderedStringMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected int
	}{
		{
			name:     "empty map",
			input:    map[string]interface{}{},
			expected: 0,
		},
		{
			name:     "single item",
			input:    map[string]interface{}{"key": "value"},
			expected: 1,
		},
		{
			name: "multiple items",
			input: map[string]interface{}{
				"a": "first",
				"b": "second",
				"c": "third",
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iosm := NewInsertionOrderedStringMap(tt.input)
			assert.Equal(t, tt.expected, iosm.Len())

			for key, expectedValue := range tt.input {
				var found bool
				iosm.ForEach(func(k string, v interface{}) {
					if k == key {
						assert.Equal(t, expectedValue, v)
						found = true
					}
				})
				assert.True(t, found, "Key %s should be found", key)
			}
		})
	}
}

func TestInsertionOrderedStringMap_ForEach(t *testing.T) {
	iosm := NewEmptyInsertionOrderedStringMap(5)
	iosm.Set("first", "1")
	iosm.Set("second", "2")
	iosm.Set("third", "3")

	var keys []string
	var values []interface{}

	iosm.ForEach(func(key string, value interface{}) {
		keys = append(keys, key)
		values = append(values, value)
	})

	assert.Equal(t, []string{"first", "second", "third"}, keys)
	assert.Equal(t, []interface{}{"1", "2", "3"}, values)
}

// Benchmark tests for performance validation
func BenchmarkInsertionOrderedStringMap_Set(b *testing.B) {
	iosm := NewEmptyInsertionOrderedStringMap(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iosm.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
	}
}

func BenchmarkInsertionOrderedStringMap_UnmarshalYAML_Small(b *testing.B) {
	yamlData := `key1: value1
key2: value2
key3: value3`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var iosm InsertionOrderedStringMap
		err := yaml.Unmarshal([]byte(yamlData), &iosm)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInsertionOrderedStringMap_UnmarshalYAML_Large(b *testing.B) {
	// Generate large YAML for stress testing
	var yamlBuilder strings.Builder
	for i := 0; i < 100; i++ {
		yamlBuilder.WriteString(fmt.Sprintf("key%d: value%d\n", i, i))
	}
	yamlData := yamlBuilder.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var iosm InsertionOrderedStringMap
		err := yaml.Unmarshal([]byte(yamlData), &iosm)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInsertionOrderedStringMap_ForEach(b *testing.B) {
	iosm := NewEmptyInsertionOrderedStringMap(1000)
	for i := 0; i < 1000; i++ {
		iosm.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iosm.ForEach(func(key string, value interface{}) {
			_ = key + value.(string)
		})
	}
}

func BenchmarkInsertionOrderedStringMap_UnmarshalJSON(b *testing.B) {
	jsonData := `{"key1":"value1","key2":"value2","key3":"value3","key4":"value4","key5":"value5"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var iosm InsertionOrderedStringMap
		err := json.Unmarshal([]byte(jsonData), &iosm)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test edge cases and error conditions
func TestInsertionOrderedStringMap_EdgeCases(t *testing.T) {
	t.Run("yaml with malformed structure", func(t *testing.T) {
		yamlData := `key: value
other: value`

		var iosm InsertionOrderedStringMap
		err := yaml.Unmarshal([]byte(yamlData), &iosm)
		assert.NoError(t, err) // YAML parser is forgiving
	})

	t.Run("very large key-value pairs", func(t *testing.T) {
		largeValue := strings.Repeat("x", 10000)
		yamlData := fmt.Sprintf("large_key: %s", largeValue)

		var iosm InsertionOrderedStringMap
		err := yaml.Unmarshal([]byte(yamlData), &iosm)
		require.NoError(t, err)

		iosm.ForEach(func(key string, value interface{}) {
			assert.Equal(t, "large_key", key)
			assert.Equal(t, largeValue, value)
		})
	})

	t.Run("unicode and special characters", func(t *testing.T) {
		yamlData := `"unicode_key_🚀": "unicode_value_🎉"
"emoji": "🔥💯"
"chinese": "你好世界"`

		var iosm InsertionOrderedStringMap
		err := yaml.Unmarshal([]byte(yamlData), &iosm)
		require.NoError(t, err)
		assert.Equal(t, 3, iosm.Len())
	})
}
