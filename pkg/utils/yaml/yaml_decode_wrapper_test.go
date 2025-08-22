package yaml

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test structs for validation
type ValidStruct struct {
	Name     string `yaml:"name" validate:"required"`
	Email    string `yaml:"email" validate:"required,email"`
	Age      int    `yaml:"age" validate:"gte=0,lte=150"`
	Username string `yaml:"username" validate:"required,min=3,max=20"`
}

type InvalidStruct struct {
	Name string `yaml:"name" validate:"required"`
	Age  int    `yaml:"age" validate:"gte=0,lte=150"`
}

type NestedStruct struct {
	User    ValidStruct `yaml:"user" validate:"required"`
	Company string      `yaml:"company" validate:"required"`
}

type SliceStruct struct {
	Items []string `yaml:"items" validate:"required,min=1"`
	Tags  []string `yaml:"tags" validate:"dive,required"`
}

func TestDecodeAndValidate(t *testing.T) {
	tests := []struct {
		name        string
		yamlInput   string
		target      interface{}
		expectError bool
		errorType   string
	}{
		{
			name: "valid struct with all fields",
			yamlInput: `name: "John Doe"
email: "john@example.com"
age: 30
username: "johndoe"`,
			target:      &ValidStruct{},
			expectError: false,
		},
		{
			name: "missing required field",
			yamlInput: `email: "john@example.com"
age: 30
username: "johndoe"`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "invalid email format",
			yamlInput: `name: "John Doe"
email: "invalid-email"
age: 30
username: "johndoe"`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "age out of range",
			yamlInput: `name: "John Doe"
email: "john@example.com"
age: 200
username: "johndoe"`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "username too short",
			yamlInput: `name: "John Doe"
email: "john@example.com"
age: 30
username: "jo"`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "username too long",
			yamlInput: `name: "John Doe"
email: "john@example.com"
age: 30
username: "very_very_very_long_username"`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "nested struct validation",
			yamlInput: `user:
  name: "John Doe"
  email: "john@example.com"
  age: 30
  username: "johndoe"
company: "TechCorp"`,
			target:      &NestedStruct{},
			expectError: false,
		},
		{
			name: "nested struct missing required field",
			yamlInput: `user:
  email: "john@example.com"
  age: 30
  username: "johndoe"
company: "TechCorp"`,
			target:      &NestedStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "slice validation success",
			yamlInput: `items: ["item1", "item2", "item3"]
tags: ["tag1", "tag2"]`,
			target:      &SliceStruct{},
			expectError: false,
		},
		{
			name: "empty slice validation failure",
			yamlInput: `items: []
tags: ["tag1", "tag2"]`,
			target:      &SliceStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "slice with empty string validation failure",
			yamlInput: `items: ["item1", "item2"]
tags: ["tag1", "", "tag3"]`,
			target:      &SliceStruct{},
			expectError: true,
			errorType:   "validation",
		},
		{
			name:        "invalid YAML syntax",
			yamlInput:   `name: "John Doe"\ninvalid: yaml: syntax`,
			target:      &ValidStruct{},
			expectError: true,
			errorType:   "yaml",
		},
		{
			name: "boundary values - minimum age",
			yamlInput: `name: "Baby"
email: "baby@example.com"
age: 0
username: "baby"`,
			target:      &ValidStruct{},
			expectError: false,
		},
		{
			name: "boundary values - maximum age",
			yamlInput: `name: "Elder"
email: "elder@example.com"
age: 150
username: "elder"`,
			target:      &ValidStruct{},
			expectError: false,
		},
		{
			name: "special characters in strings",
			yamlInput: `name: "José María"
email: "jose@example.com"
age: 25
username: "jose123"`,
			target:      &ValidStruct{},
			expectError: false,
		},
		{
			name:        "invalid validation error test",
			yamlInput:   `name: "test"`,
			target:      "invalid_target", // This should cause InvalidValidationError
			expectError: true,
			errorType:   "invalid_validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.yamlInput)
			err := DecodeAndValidate(reader, tt.target)

			if tt.expectError {
				assert.Error(t, err)

				switch tt.errorType {
				case "yaml":
					assert.Contains(t, err.Error(), "yaml")
				case "validation":
					assert.Contains(t, err.Error(), "validation failed")
				case "invalid_validation":
					// This should not wrap with "validation failed"
					assert.NotContains(t, err.Error(), "validation failed")
				}
			} else {
				assert.NoError(t, err)

				// Additional validation for successful cases
				if vs, ok := tt.target.(*ValidStruct); ok {
					assert.NotEmpty(t, vs.Name)
					assert.NotEmpty(t, vs.Email)
					assert.GreaterOrEqual(t, vs.Age, 0)
					assert.LessOrEqual(t, vs.Age, 150)
				}
			}
		})
	}
}

func TestDecodeAndValidate_ReaderTypes(t *testing.T) {
	yamlData := `name: "John Doe"
email: "john@example.com"
age: 30
username: "johndoe"`

	readerTypes := []struct {
		name   string
		reader io.Reader
	}{
		{
			name:   "strings.Reader",
			reader: strings.NewReader(yamlData),
		},
		{
			name:   "bytes.Buffer",
			reader: bytes.NewBufferString(yamlData),
		},
		{
			name:   "bytes.Reader",
			reader: bytes.NewReader([]byte(yamlData)),
		},
	}

	for _, rt := range readerTypes {
		t.Run(rt.name, func(t *testing.T) {
			var target ValidStruct
			err := DecodeAndValidate(rt.reader, &target)
			require.NoError(t, err)
			assert.Equal(t, "John Doe", target.Name)
			assert.Equal(t, "john@example.com", target.Email)
			assert.Equal(t, 30, target.Age)
			assert.Equal(t, "johndoe", target.Username)
		})
	}
}

func TestDecodeAndValidate_EmptyInput(t *testing.T) {
	tests := []struct {
		name      string
		yamlInput string
		target    interface{}
	}{
		{
			name:      "empty string",
			yamlInput: "",
			target:    &ValidStruct{},
		},
		{
			name:      "only whitespace",
			yamlInput: "   \n\t  ",
			target:    &ValidStruct{},
		},
		{
			name:      "empty YAML document",
			yamlInput: "---\n",
			target:    &ValidStruct{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.yamlInput)
			err := DecodeAndValidate(reader, tt.target)
			// Empty input should fail YAML parsing or validation
			assert.Error(t, err)
		})
	}
}

func TestDecodeAndValidate_ConcurrentAccess(t *testing.T) {
	yamlData := `name: "John Doe"
email: "john@example.com"
age: 30
username: "johndoe"`

	// Test concurrent access to ensure validator is thread-safe
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				var target ValidStruct
				reader := strings.NewReader(yamlData)
				err := DecodeAndValidate(reader, &target)
				assert.NoError(t, err)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Benchmark tests for performance validation
func BenchmarkDecodeAndValidate_Small(b *testing.B) {
	yamlData := `name: "John Doe"
email: "john@example.com"
age: 30
username: "johndoe"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var target ValidStruct
		reader := strings.NewReader(yamlData)
		err := DecodeAndValidate(reader, &target)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeAndValidate_Large(b *testing.B) {
	// Generate large YAML for stress testing
	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("items:\n")
	for i := 0; i < 1000; i++ {
		yamlBuilder.WriteString(fmt.Sprintf("  - \"item%d\"\n", i))
	}
	yamlBuilder.WriteString("tags:\n")
	for i := 0; i < 100; i++ {
		yamlBuilder.WriteString(fmt.Sprintf("  - \"tag%d\"\n", i))
	}
	yamlData := yamlBuilder.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var target SliceStruct
		reader := strings.NewReader(yamlData)
		err := DecodeAndValidate(reader, &target)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeAndValidate_NestedStruct(b *testing.B) {
	yamlData := `user:
  name: "John Doe"
  email: "john@example.com"
  age: 30
  username: "johndoe"
company: "TechCorp"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var target NestedStruct
		reader := strings.NewReader(yamlData)
		err := DecodeAndValidate(reader, &target)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeAndValidate_ValidationOnly(b *testing.B) {
	// YAML to test validation path
	yamlData := `name: "John Doe"
email: "john@example.com"  
age: 30
username: "johndoe"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var testTarget ValidStruct
		reader := strings.NewReader(yamlData)
		err := DecodeAndValidate(reader, &testTarget)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test memory usage patterns
func TestDecodeAndValidate_MemoryUsage(t *testing.T) {
	// Test with various sizes to ensure no memory leaks
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			var yamlBuilder strings.Builder
			yamlBuilder.WriteString("items:\n")
			for i := 0; i < size; i++ {
				yamlBuilder.WriteString(fmt.Sprintf("  - \"item%d\"\n", i))
			}
			yamlBuilder.WriteString("tags:\n")
			for i := 0; i < size/10; i++ {
				yamlBuilder.WriteString(fmt.Sprintf("  - \"tag%d\"\n", i))
			}
			yamlData := yamlBuilder.String()

			var target SliceStruct
			reader := strings.NewReader(yamlData)
			err := DecodeAndValidate(reader, &target)
			require.NoError(t, err)
			assert.Equal(t, size, len(target.Items))
			assert.Equal(t, size/10, len(target.Tags))
		})
	}
}
