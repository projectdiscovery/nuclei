package yaml

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreProcess(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-preprocess-test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	includeFile1 := filepath.Join(tempDir, "include1.yaml")
	includeContent1 := `included_key1: included_value1
included_key2: included_value2`
	err = os.WriteFile(includeFile1, []byte(includeContent1), 0644)
	require.NoError(t, err)

	includeFile2 := filepath.Join(tempDir, "include2.yaml")
	includeContent2 := `nested:
  key: value
  items:
    - item1
    - item2`
	err = os.WriteFile(includeFile2, []byte(includeContent2), 0644)
	require.NoError(t, err)

	includeFile3 := filepath.Join(tempDir, "include3.yaml")
	includeContent3 := fmt.Sprintf(`# !include:%s
additional_key: additional_value`, includeFile1)
	err = os.WriteFile(includeFile3, []byte(includeContent3), 0644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       string
		expected    string
		strictMode  bool
		expectError bool
		setup       func()
	}{
		{
			name: "simple include",
			input: fmt.Sprintf(`main_key: main_value
# !include:%s
another_key: another_value`, includeFile1),
			expected: fmt.Sprintf(`main_key: main_value
%s
another_key: another_value`, includeContent1),
			strictMode: false,
		},
		{
			name: "multiple includes",
			input: fmt.Sprintf(`# !include:%s
separator: "---"
# !include:%s`, includeFile1, includeFile2),
			expected:   fmt.Sprintf("%s\nseparator: \"---\"\n%s", includeContent1, includeContent2),
			strictMode: false,
		},
		{
			name:       "nested include (recursive)",
			input:      fmt.Sprintf(`# !include:%s`, includeFile3),
			expected:   fmt.Sprintf("%s\nadditional_key: additional_value", includeContent1),
			strictMode: false,
		},
		{
			name: "include with indentation",
			input: fmt.Sprintf(`main:
  section1:
    # !include:%s
  section2:
    key: value`, includeFile1),
			expected: fmt.Sprintf(`main:
  section1:
    %s
  section2:
    key: value`, strings.ReplaceAll(includeContent1, "\n", "\n    ")),
			strictMode: false,
		},
		{
			name: "include non-existent file",
			input: `# !include:non_existent_file.yaml
main_key: main_value`,
			expected: `# !include:non_existent_file.yaml
main_key: main_value`,
			strictMode: false,
		},
		{
			name:        "strict mode with include",
			input:       fmt.Sprintf(`# !include:%s`, includeFile1),
			strictMode:  true,
			expectError: true,
		},
		{
			name: "no includes",
			input: `main_key: main_value
another_key: another_value`,
			expected: `main_key: main_value
another_key: another_value`,
			strictMode: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name: "include with complex indentation",
			input: fmt.Sprintf(`template:
  requests:
    - method: GET
      path:
        # !include:%s
      headers:
        User-Agent: test`, includeFile1),
			expected: fmt.Sprintf(`template:
  requests:
    - method: GET
      path:
        %s
      headers:
        User-Agent: test`, strings.ReplaceAll(includeContent1, "\n", "\n        ")),
		},
		{
			name: "multiple includes with different indentation",
			input: fmt.Sprintf(`level1:
  # !include:%s
  level2:
    # !include:%s`, includeFile1, includeFile2),
			expected: fmt.Sprintf(`level1:
  %s
  level2:
    %s`,
				strings.ReplaceAll(includeContent1, "\n", "\n  "),
				strings.ReplaceAll(includeContent2, "\n", "\n    ")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set strict mode
			originalStrictSyntax := StrictSyntax
			StrictSyntax = tt.strictMode
			defer func() { StrictSyntax = originalStrictSyntax }()

			if tt.setup != nil {
				tt.setup()
			}

			result, err := PreProcess([]byte(tt.input))

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestPreProcess_EdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-preprocess-edge-test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	tests := []struct {
		name        string
		setup       func() (string, error)
		expectError bool
		description string
	}{
		{
			name: "binary file include",
			setup: func() (string, error) {
				binFile := filepath.Join(tempDir, "binary.bin")
				binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
				err := os.WriteFile(binFile, binaryData, 0644)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("# !include:%s", binFile), nil
			},
			expectError: false,
		},
		{
			name: "large recursive includes",
			setup: func() (string, error) {
				largeFile := filepath.Join(tempDir, "large_recursive.yaml")
				var content strings.Builder
				for i := 0; i < 100; i++ {
					content.WriteString(fmt.Sprintf("key%d: value%d\n", i, i))
				}
				err := os.WriteFile(largeFile, []byte(content.String()), 0644)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("# !include:%s", largeFile), nil
			},
			expectError: false,
		},
		{
			name: "very large include file",
			setup: func() (string, error) {
				largeFile := filepath.Join(tempDir, "large.yaml")
				var content strings.Builder
				for i := 0; i < 10000; i++ {
					content.WriteString(fmt.Sprintf("key%d: value%d\n", i, i))
				}
				err := os.WriteFile(largeFile, []byte(content.String()), 0644)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("# !include:%s", largeFile), nil
			},
			expectError: false,
		},
		{
			name: "include with special characters in filename",
			setup: func() (string, error) {
				specialFile := filepath.Join(tempDir, "special-file_name.yaml")
				content := "special_key: special_value"
				err := os.WriteFile(specialFile, []byte(content), 0644)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("# !include:%s", specialFile), nil
			},
			expectError: false,
		},
		{
			name: "permission denied file",
			setup: func() (string, error) {
				if os.Getuid() == 0 { // Skip if running as root
					t.Skip("Skipping permission test when running as root")
				}

				restrictedFile := filepath.Join(tempDir, "restricted.yaml")
				content := "restricted: content"
				err := os.WriteFile(restrictedFile, []byte(content), 0000)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("# !include:%s", restrictedFile), nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := tt.setup()
			require.NoError(t, err)

			StrictSyntax = false
			result, err := PreProcess([]byte(input))

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestPreProcess_StrictSyntax(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		strictMode  bool
		expectError bool
	}{
		{
			name:        "strict mode enabled with include",
			input:       "# !include:somefile.yaml",
			strictMode:  true,
			expectError: true,
		},
		{
			name:        "strict mode disabled with include",
			input:       "# !include:somefile.yaml",
			strictMode:  false,
			expectError: false,
		},
		{
			name:       "strict mode enabled without include",
			input:      "normal: yaml\ncontent: here",
			strictMode: true,
		},
		{
			name:       "strict mode disabled without include",
			input:      "normal: yaml\ncontent: here",
			strictMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalStrictSyntax := StrictSyntax
			StrictSyntax = tt.strictMode
			defer func() { StrictSyntax = originalStrictSyntax }()

			result, err := PreProcess([]byte(tt.input))

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "include directive preprocessing is disabled")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestPreProcess_IncludePatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "single include",
			input:    "# !include:file.yaml",
			expected: 1,
		},
		{
			name:     "multiple includes",
			input:    "# !include:file1.yaml\n# !include:file2.yaml",
			expected: 2,
		},
		{
			name:     "include in comment",
			input:    "# This is a comment with !include:file.yaml inside",
			expected: 0,
		},
		{
			name:     "malformed include",
			input:    "!include:file.yaml",
			expected: 0,
		},
		{
			name:     "include with spaces",
			input:    "#  !include:file.yaml",
			expected: 0,
		},
		{
			name:     "include with relative path",
			input:    "# !include:../relative/path.yaml",
			expected: 1,
		},
		{
			name:     "include with absolute path",
			input:    "# !include:/absolute/path.yaml",
			expected: 1,
		},
		{
			name:     "no includes",
			input:    "normal: yaml\ncontent: without includes",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := reImportsPattern.FindAllSubmatch([]byte(tt.input), -1)
			assert.Equal(t, tt.expected, len(matches))
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkPreProcess_NoIncludes(b *testing.B) {
	yamlData := `template:
  name: "Test Template"
  author: "Test Author"
  severity: medium
  requests:
    - method: GET
      path: /test
      headers:
        User-Agent: test`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PreProcess([]byte(yamlData))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreProcess_WithIncludes(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "nuclei-benchmark-preprocess")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	includeFile := filepath.Join(tempDir, "include.yaml")
	includeContent := `included_key: included_value
another_key: another_value`
	err = os.WriteFile(includeFile, []byte(includeContent), 0644)
	if err != nil {
		b.Fatal(err)
	}

	yamlData := fmt.Sprintf(`template:
  name: "Test Template"
  # !include:%s
  requests:
    - method: GET`, includeFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PreProcess([]byte(yamlData))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreProcess_MultipleIncludes(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "nuclei-benchmark-multi-preprocess")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("template:\n  name: \"Test Template\"\n")

	for i := 0; i < 10; i++ {
		includeFile := filepath.Join(tempDir, fmt.Sprintf("include%d.yaml", i))
		includeContent := fmt.Sprintf("key%d: value%d\ndata%d: content%d", i, i, i, i)
		err = os.WriteFile(includeFile, []byte(includeContent), 0644)
		if err != nil {
			b.Fatal(err)
		}
		yamlBuilder.WriteString(fmt.Sprintf("  # !include:%s\n", includeFile))
	}

	yamlData := yamlBuilder.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PreProcess([]byte(yamlData))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreProcess_LargeFile(b *testing.B) {
	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("template:\n")
	for i := 0; i < 10000; i++ {
		yamlBuilder.WriteString(fmt.Sprintf("  key%d: value%d\n", i, i))
	}
	yamlData := yamlBuilder.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PreProcess([]byte(yamlData))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreProcess_NestedIncludes(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "nuclei-benchmark-nested-preprocess")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	files := make([]string, 5)
	for i := 0; i < 5; i++ {
		files[i] = filepath.Join(tempDir, fmt.Sprintf("nested%d.yaml", i))
	}

	for i := 0; i < 4; i++ {
		content := fmt.Sprintf("key%d: value%d\n# !include:%s", i, i, files[i+1])
		err = os.WriteFile(files[i], []byte(content), 0644)
		if err != nil {
			b.Fatal(err)
		}
	}

	lastContent := "final_key: final_value"
	err = os.WriteFile(files[4], []byte(lastContent), 0644)
	if err != nil {
		b.Fatal(err)
	}

	yamlData := fmt.Sprintf("# !include:%s", files[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PreProcess([]byte(yamlData))
		if err != nil {
			b.Fatal(err)
		}
	}
}
