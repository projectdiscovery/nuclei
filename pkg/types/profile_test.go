package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestPreprocessProfileFile_NoSpecialKeys verifies that when a profile has
// no extra fields, no inline targets, and no inline secrets, the original
// file path is returned unchanged with no temporary files created.
func TestPreprocessProfileFile_NoSpecialKeys(t *testing.T) {
	content := `tags:
  - kev
timeout: 30
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should return original path since no preprocessing was needed
	require.Equal(t, tmpFile, result.CleanedConfigPath)
	require.Empty(t, result.TempFiles)
	require.Empty(t, result.InlineTargetsFile)
	require.Empty(t, result.InlineSecretsFile)
}

// TestPreprocessProfileFile_ExtraFieldsRemoved verifies Feature 1:
// extra metadata fields (id, name, purpose, description) are silently
// stripped from the cleaned config so goflags won't error on unknown keys.
func TestPreprocessProfileFile_ExtraFieldsRemoved(t *testing.T) {
	content := `id: my-scan-profile
name: projectdiscovery-scan
purpose: Config File for Scanning
description: single config file for scanning a specific target
tags:
  - kev
timeout: 30
stats: true
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should have created a cleaned config (different path from original)
	require.NotEqual(t, tmpFile, result.CleanedConfigPath)
	require.FileExists(t, result.CleanedConfigPath)

	// Read and parse the cleaned config
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	// Extra fields must be absent
	_, hasID := cleaned["id"]
	require.False(t, hasID, "id field should have been removed")
	_, hasName := cleaned["name"]
	require.False(t, hasName, "name field should have been removed")
	_, hasPurpose := cleaned["purpose"]
	require.False(t, hasPurpose, "purpose field should have been removed")
	_, hasDesc := cleaned["description"]
	require.False(t, hasDesc, "description field should have been removed")

	// Regular fields must still be present
	_, hasTags := cleaned["tags"]
	require.True(t, hasTags, "tags field should be preserved")
	_, hasTimeout := cleaned["timeout"]
	require.True(t, hasTimeout, "timeout field should be preserved")
	_, hasStats := cleaned["stats"]
	require.True(t, hasStats, "stats field should be preserved")
}

// TestPreprocessProfileFile_InlineTargets verifies Feature 2:
// a multiline `list` value is extracted to a temp file and the
// `list` key in the cleaned config points to that temp file.
func TestPreprocessProfileFile_InlineTargets(t *testing.T) {
	content := `list: |
  cve.projectdiscovery.io
  chaos.projectdiscovery.io
  api.projectdiscovery.io
tags:
  - kev
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should have created an inline targets temp file
	require.NotEmpty(t, result.InlineTargetsFile)
	require.FileExists(t, result.InlineTargetsFile)

	// Read the targets file and verify contents
	targetsData, err := os.ReadFile(result.InlineTargetsFile)
	require.NoError(t, err)

	targets := parseLines(string(targetsData))
	require.Equal(t, 3, len(targets))
	require.Contains(t, targets, "cve.projectdiscovery.io")
	require.Contains(t, targets, "chaos.projectdiscovery.io")
	require.Contains(t, targets, "api.projectdiscovery.io")

	// The cleaned config's "list" value should be the temp file path
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	listVal, ok := cleaned["list"]
	require.True(t, ok, "list key should still exist in cleaned config")
	listStr, ok := listVal.(string)
	require.True(t, ok, "list value should be a string (temp file path)")
	require.Equal(t, result.InlineTargetsFile, listStr)
}

// TestPreprocessProfileFile_SingleLineListUnchanged verifies that a
// single-line `list` value (a normal file path) is NOT treated as
// inline targets and is left untouched.
func TestPreprocessProfileFile_SingleLineListUnchanged(t *testing.T) {
	content := `name: test-profile
list: /path/to/targets.txt
tags:
  - kev
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// No inline targets file should be created
	require.Empty(t, result.InlineTargetsFile)

	// The list value should remain unchanged (still a file path)
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	listVal, ok := cleaned["list"]
	require.True(t, ok, "list key should still exist")
	require.Equal(t, "/path/to/targets.txt", listVal)
}

// TestPreprocessProfileFile_InlineSecrets verifies Feature 3:
// a `secrets` key with static/dynamic sub-keys is extracted to a
// temp file in authx format and linked via `secret-file`.
func TestPreprocessProfileFile_InlineSecrets(t *testing.T) {
	content := `tags:
  - kev
secrets:
  static:
    - type: header
      domains:
        - api.projectdiscovery.io
      headers:
        - key: x-pdcp-key
          value: test-api-key
  dynamic:
    - template: custom-oauth-flow.yaml
      variables:
        - name: username
          value: pdteam
        - name: password
          value: nuclei-fuzz
      type: cookie
      domains:
        - scanme.sh
      cookies:
        - raw: "{{session-cookie}}"
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should have created an inline secrets temp file
	require.NotEmpty(t, result.InlineSecretsFile)
	require.FileExists(t, result.InlineSecretsFile)

	// Read and parse the secrets file — it should be valid authx YAML
	secretsData, err := os.ReadFile(result.InlineSecretsFile)
	require.NoError(t, err)

	var authxData map[string]interface{}
	err = yaml.Unmarshal(secretsData, &authxData)
	require.NoError(t, err)

	// Verify static key exists
	_, hasStatic := authxData["static"]
	require.True(t, hasStatic, "secrets file should contain static key")

	// Verify dynamic key exists
	_, hasDynamic := authxData["dynamic"]
	require.True(t, hasDynamic, "secrets file should contain dynamic key")

	// The cleaned config should NOT have a "secrets" key
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	_, hasSecrets := cleaned["secrets"]
	require.False(t, hasSecrets, "secrets key should have been removed from cleaned config")

	// The cleaned config should have a "secret-file" key pointing to the temp file
	sfVal, hasSF := cleaned["secret-file"]
	require.True(t, hasSF, "secret-file key should exist in cleaned config")
	sfStr, ok := sfVal.(string)
	require.True(t, ok, "secret-file value should be a string")
	require.Contains(t, sfStr, filepath.ToSlash(result.InlineSecretsFile))
}

// TestPreprocessProfileFile_InlineSecretsAppendToExisting verifies that
// when a profile already has a `secret-file` value, the inline secrets
// temp file path is appended (comma-separated) rather than replacing it.
func TestPreprocessProfileFile_InlineSecretsAppendToExisting(t *testing.T) {
	content := `secret-file: /existing/secrets.yaml
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: Authorization
          value: Bearer existing-token
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	require.NotEmpty(t, result.InlineSecretsFile)

	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	sfVal, hasSF := cleaned["secret-file"]
	require.True(t, hasSF)
	sfStr, ok := sfVal.(string)
	require.True(t, ok)

	// Should contain both the original path and the new inline secrets path
	require.Contains(t, sfStr, "/existing/secrets.yaml")
	require.Contains(t, sfStr, filepath.ToSlash(result.InlineSecretsFile))
	require.Contains(t, sfStr, ",", "should be comma-separated")
}

// TestPreprocessProfileFile_FullProfile verifies the complete end-to-end
// scenario from the GitHub issue: a profile with metadata fields, inline
// targets, inline secrets, and regular nuclei flags all at once.
func TestPreprocessProfileFile_FullProfile(t *testing.T) {
	content := `name: projectdiscovery-scan
purpose: Config File for Scanning
description: single config file that contains every config related to scanning

list: |
  cve.projectdiscovery.io
  chaos.projectdiscovery.io
  api.projectdiscovery.io

type:
  - http
  - tcp
  - javascript
  - dns
  - ssl

exclude-tags:
  - dos
  - fuzz
  - osint

concurrency: 5
bulk-size: 100
stats: true
timeout: 30

secrets:
  static:
    - type: header
      domains:
        - api.projectdiscovery.io
        - cve.projectdiscovery.io
        - chaos.projectdiscovery.io
      headers:
        - key: x-pdcp-key
          value: test-api-key-here
  dynamic:
    - template: custom-oauth-flow.yaml
      variables:
        - name: username
          value: pdteam
        - name: password
          value: nuclei-fuzz
      type: cookie
      domains:
        - scanme.sh
      cookies:
        - raw: "{{session-cookie}}"
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// All three features should have produced results
	require.NotEqual(t, tmpFile, result.CleanedConfigPath)
	require.NotEmpty(t, result.InlineTargetsFile)
	require.NotEmpty(t, result.InlineSecretsFile)

	// Verify targets file
	targetsData, err := os.ReadFile(result.InlineTargetsFile)
	require.NoError(t, err)
	targets := parseLines(string(targetsData))
	require.Equal(t, 3, len(targets))

	// Verify secrets file has both static and dynamic
	secretsData, err := os.ReadFile(result.InlineSecretsFile)
	require.NoError(t, err)
	var authx map[string]interface{}
	err = yaml.Unmarshal(secretsData, &authx)
	require.NoError(t, err)
	_, hasStatic := authx["static"]
	require.True(t, hasStatic)
	_, hasDynamic := authx["dynamic"]
	require.True(t, hasDynamic)

	// Verify cleaned config
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)
	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	// Extra fields removed
	for field := range profileExtraFields {
		_, exists := cleaned[field]
		require.False(t, exists, "field %q should have been removed", field)
	}

	// secrets key removed
	_, hasSecrets := cleaned["secrets"]
	require.False(t, hasSecrets, "secrets key should have been removed")

	// Regular flags preserved
	_, hasType := cleaned["type"]
	require.True(t, hasType, "type field should be preserved")
	_, hasExcludeTags := cleaned["exclude-tags"]
	require.True(t, hasExcludeTags, "exclude-tags field should be preserved")
	_, hasStats := cleaned["stats"]
	require.True(t, hasStats, "stats field should be preserved")
	_, hasTimeout := cleaned["timeout"]
	require.True(t, hasTimeout, "timeout field should be preserved")
	_, hasConcurrency := cleaned["concurrency"]
	require.True(t, hasConcurrency, "concurrency field should be preserved")
	_, hasBulkSize := cleaned["bulk-size"]
	require.True(t, hasBulkSize, "bulk-size field should be preserved")

	// list key should now be the temp file path
	listVal, hasList := cleaned["list"]
	require.True(t, hasList)
	listStr, ok := listVal.(string)
	require.True(t, ok)
	require.Equal(t, result.InlineTargetsFile, listStr)

	// secret-file key should reference the temp secrets file
	sfVal, hasSF := cleaned["secret-file"]
	require.True(t, hasSF)
	sfStr, ok := sfVal.(string)
	require.True(t, ok)
	require.Contains(t, sfStr, filepath.ToSlash(result.InlineSecretsFile))
}

// TestPreprocessProfileFile_Cleanup verifies that Cleanup() removes
// all temporary files that were created during preprocessing.
func TestPreprocessProfileFile_Cleanup(t *testing.T) {
	content := `name: cleanup-test
list: |
  example.com
  test.com
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: X-Token
          value: test
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Gather all temp file paths before cleanup
	allTempFiles := make([]string, len(result.TempFiles))
	copy(allTempFiles, result.TempFiles)

	// All temp files should exist before cleanup
	for _, f := range allTempFiles {
		require.FileExists(t, f)
	}

	// Run cleanup
	result.Cleanup()

	// All temp files should be gone after cleanup
	for _, f := range allTempFiles {
		_, err := os.Stat(f)
		require.True(t, os.IsNotExist(err), "temp file %q should have been removed by Cleanup()", f)
	}
}

// TestPreprocessProfileFile_EmptyInlineTargets verifies that when the
// `list` multiline block contains only whitespace/empty lines, the
// `list` key is removed entirely and no temp file is created.
func TestPreprocessProfileFile_EmptyInlineTargets(t *testing.T) {
	content := `name: empty-targets
list: |


`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// No inline targets file should be created for empty content
	require.Empty(t, result.InlineTargetsFile)

	// The cleaned config should not have the list key
	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)
	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	_, hasList := cleaned["list"]
	require.False(t, hasList, "empty inline list should be removed")
}

// TestPreprocessProfileFile_SecretsNotMap verifies that if the `secrets`
// value is not a map (e.g., a string or scalar), it is silently ignored
// and no temp file is created.
func TestPreprocessProfileFile_SecretsNotMap(t *testing.T) {
	content := `name: bad-secrets
secrets: not-a-map-value
tags:
  - kev
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// No inline secrets file since secrets was not a map
	require.Empty(t, result.InlineSecretsFile)
}

// TestPreprocessProfileFile_SecretsStaticOnly verifies that secrets with
// only a "static" key (no "dynamic") works correctly.
func TestPreprocessProfileFile_SecretsStaticOnly(t *testing.T) {
	content := `secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: X-API-Key
          value: my-key
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	require.NotEmpty(t, result.InlineSecretsFile)

	secretsData, err := os.ReadFile(result.InlineSecretsFile)
	require.NoError(t, err)

	var authx map[string]interface{}
	err = yaml.Unmarshal(secretsData, &authx)
	require.NoError(t, err)

	_, hasStatic := authx["static"]
	require.True(t, hasStatic, "static key should be present")
	_, hasDynamic := authx["dynamic"]
	require.False(t, hasDynamic, "dynamic key should not be present")
}

// TestPreprocessProfileFile_SecretsDynamicOnly verifies that secrets with
// only a "dynamic" key (no "static") works correctly.
func TestPreprocessProfileFile_SecretsDynamicOnly(t *testing.T) {
	content := `secrets:
  dynamic:
    - template: login-flow.yaml
      variables:
        - name: user
          value: admin
      type: cookie
      domains:
        - example.com
      cookies:
        - raw: "{{auth-cookie}}"
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	require.NotEmpty(t, result.InlineSecretsFile)

	secretsData, err := os.ReadFile(result.InlineSecretsFile)
	require.NoError(t, err)

	var authx map[string]interface{}
	err = yaml.Unmarshal(secretsData, &authx)
	require.NoError(t, err)

	_, hasStatic := authx["static"]
	require.False(t, hasStatic, "static key should not be present")
	_, hasDynamic := authx["dynamic"]
	require.True(t, hasDynamic, "dynamic key should be present")
}

// TestPreprocessProfileFile_SecretsEmptyStaticDynamic verifies that when
// both static and dynamic are absent from the secrets map, no temp file
// is created.
func TestPreprocessProfileFile_SecretsEmptyStaticDynamic(t *testing.T) {
	content := `name: empty-secrets
secrets:
  something-else: true
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// No secrets file because neither static nor dynamic were present
	require.Empty(t, result.InlineSecretsFile)
}

// TestPreprocessProfileFile_NonExistentFile verifies that a non-existent
// file path returns an error.
func TestPreprocessProfileFile_NonExistentFile(t *testing.T) {
	result, err := PreprocessProfileFile("/non/existent/path/profile.yaml")
	require.Error(t, err)
	require.Nil(t, result)
}

// TestPreprocessProfileFile_InvalidYAML verifies that an invalid YAML file
// returns an error.
func TestPreprocessProfileFile_InvalidYAML(t *testing.T) {
	content := `{{{invalid yaml content!!!`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.Error(t, err)
	require.Nil(t, result)
}

// TestPreprocessProfileFile_OnlyExtraFields verifies that a profile with
// ONLY extra fields (and nothing else) produces a cleaned config that is
// essentially empty.
func TestPreprocessProfileFile_OnlyExtraFields(t *testing.T) {
	content := `id: test-id
name: test-name
purpose: testing
description: a test profile with only metadata
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should have preprocessed since extra fields were present
	require.NotEqual(t, tmpFile, result.CleanedConfigPath)

	cleanedData, err := os.ReadFile(result.CleanedConfigPath)
	require.NoError(t, err)

	var cleaned map[string]interface{}
	err = yaml.Unmarshal(cleanedData, &cleaned)
	require.NoError(t, err)

	// All extra fields should be gone, resulting in an empty map
	require.Empty(t, cleaned)
}

// TestPreprocessProfileFile_TempFileCount verifies the correct number
// of temp files are tracked for a full profile scenario.
func TestPreprocessProfileFile_TempFileCount(t *testing.T) {
	content := `name: temp-count-test
list: |
  target1.com
  target2.com
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: X-Key
          value: val
`
	tmpFile := writeTempYAML(t, content)
	defer os.Remove(tmpFile)

	result, err := PreprocessProfileFile(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Cleanup()

	// Should have 3 temp files: cleaned config, targets, secrets
	require.Equal(t, 3, len(result.TempFiles))
}

// TestHasSpecialKeys verifies the hasSpecialKeys helper function.
func TestHasSpecialKeys(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected bool
	}{
		{
			name:     "no special keys",
			config:   map[string]interface{}{"tags": []string{"kev"}, "timeout": 30},
			expected: false,
		},
		{
			name:     "has id",
			config:   map[string]interface{}{"id": "test", "tags": []string{"kev"}},
			expected: true,
		},
		{
			name:     "has name",
			config:   map[string]interface{}{"name": "test"},
			expected: true,
		},
		{
			name:     "has purpose",
			config:   map[string]interface{}{"purpose": "test"},
			expected: true,
		},
		{
			name:     "has description",
			config:   map[string]interface{}{"description": "test"},
			expected: true,
		},
		{
			name:     "has secrets",
			config:   map[string]interface{}{"secrets": map[string]interface{}{}},
			expected: true,
		},
		{
			name:     "has multiline list",
			config:   map[string]interface{}{"list": "target1\ntarget2"},
			expected: true,
		},
		{
			name:     "has single-line list (file path)",
			config:   map[string]interface{}{"list": "/path/to/file.txt"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasSpecialKeys(tc.config)
			require.Equal(t, tc.expected, result)
		})
	}
}

// --- helpers ---

// writeTempYAML creates a temporary YAML file with the given content
// and returns its path. The caller is responsible for removing it.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "nuclei-test-profile-*.yaml")
	require.NoError(t, err)
	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	_ = tmpFile.Close()
	return tmpFile.Name()
}

// parseLines splits text by newlines and returns non-empty trimmed lines.
func parseLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
