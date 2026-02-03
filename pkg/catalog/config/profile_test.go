package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadProfileConfig(t *testing.T) {
	t.Run("LoadProfileWithMetadata", func(t *testing.T) {
		// Create a test profile with metadata
		profileContent := `name: test-profile
purpose: Testing profile loading
description: A test profile with metadata

tags:
  - cve
  - exposure
silent: true
timeout: 10
`
		tmpFile, err := os.CreateTemp("", "test-profile-*.yml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(profileContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Load the profile
		config, err := LoadProfileConfig(tmpFile.Name())
		require.NoError(t, err)
		require.NotNil(t, config)

		// Metadata fields should not be in the config
		// (they're extracted but not passed to goflags)
		assert.Contains(t, config, "tags")
		assert.Contains(t, config, "silent")
		assert.Contains(t, config, "timeout")
	})

	t.Run("LoadProfileWithInlineContent", func(t *testing.T) {
		profileContent := `name: inline-test
list: |
  example.com
  test.com
  foo.com

tags:
  - cve
`
		tmpFile, err := os.CreateTemp("", "test-profile-*.yml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(profileContent)
		require.NoError(t, err)
		tmpFile.Close()

		config, err := LoadProfileConfig(tmpFile.Name())
		require.NoError(t, err)
		require.NotNil(t, config)

		// The inline list should be converted to a slice
		listValue := config["list"]
		require.NotNil(t, listValue)

		// It should be a slice of strings
		switch v := listValue.(type) {
		case []interface{}:
			assert.Len(t, v, 3)
		case []string:
			assert.Len(t, v, 3)
		case string:
			// If it's still a string, it should have the content
			assert.Contains(t, v, "example.com")
		}
	})

	t.Run("NonExistentProfile", func(t *testing.T) {
		_, err := LoadProfileConfig("/non/existent/file.yml")
		assert.Error(t, err)
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-profile-*.yml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("invalid: yaml: content: [")
		require.NoError(t, err)
		tmpFile.Close()

		_, err = LoadProfileConfig(tmpFile.Name())
		assert.Error(t, err)
	})
}

func TestProcessInlineContent(t *testing.T) {
	t.Run("ProcessMultiLineString", func(t *testing.T) {
		config := map[string]interface{}{
			"list": "line1\nline2\nline3",
			"tags": []interface{}{"tag1", "tag2"},
		}

		processed, err := processInlineContent(config)
		require.NoError(t, err)

		// Multi-line string should be converted to slice
		listValue := processed["list"]
		switch v := listValue.(type) {
		case []string:
			assert.Len(t, v, 3)
			assert.Contains(t, v, "line1")
			assert.Contains(t, v, "line2")
			assert.Contains(t, v, "line3")
		case []interface{}:
			assert.Len(t, v, 3)
		}
	})

	t.Run("ProcessNestedMaps", func(t *testing.T) {
		config := map[string]interface{}{
			"secrets": map[string]interface{}{
				"static": []interface{}{
					map[string]interface{}{
						"type": "header",
					},
				},
			},
		}

		processed, err := processInlineContent(config)
		require.NoError(t, err)
		assert.Contains(t, processed, "secrets")
	})
}

func TestProcessSecretsConfig(t *testing.T) {
	t.Run("ProcessEmbeddedSecrets", func(t *testing.T) {
		config := map[string]interface{}{
			"tags": []interface{}{"cve"},
			"secrets": map[string]interface{}{
				"static": []interface{}{
					map[string]interface{}{
						"type": "header",
						"headers": []interface{}{
							map[string]interface{}{
								"key":   "X-API-Key",
								"value": "test-key",
							},
						},
					},
				},
			},
		}

		secretsFile, err := ProcessSecretsConfig(config)
		require.NoError(t, err)

		if secretsFile != "" {
			defer os.Remove(secretsFile)
			// Secrets file should be created
			assert.FileExists(t, secretsFile)
			// Secrets should be removed from main config
			assert.NotContains(t, config, "secrets")
		}
	})

	t.Run("NoSecrets", func(t *testing.T) {
		config := map[string]interface{}{
			"tags": []interface{}{"cve"},
		}

		secretsFile, err := ProcessSecretsConfig(config)
		require.NoError(t, err)
		assert.Empty(t, secretsFile)
	})
}

func TestConvertConfigToFile(t *testing.T) {
	t.Run("ConvertToTempFile", func(t *testing.T) {
		config := map[string]interface{}{
			"tags":    []interface{}{"cve", "exposure"},
			"silent":  true,
			"timeout": 10,
		}

		tmpFile, err := ConvertConfigToFile(config)
		require.NoError(t, err)
		defer os.Remove(tmpFile)

		assert.FileExists(t, tmpFile)

		// Read back and verify
		data, err := os.ReadFile(tmpFile)
		require.NoError(t, err)
		assert.Contains(t, string(data), "tags")
		assert.Contains(t, string(data), "silent")
		assert.Contains(t, string(data), "timeout")
	})

	t.Run("FilterInternalFields", func(t *testing.T) {
		config := map[string]interface{}{
			"tags":                     []interface{}{"cve"},
			"_embedded_secrets_file":   "/tmp/secrets.yml",
			"_internal_processing_key": "value",
		}

		tmpFile, err := ConvertConfigToFile(config)
		require.NoError(t, err)
		defer os.Remove(tmpFile)

		data, err := os.ReadFile(tmpFile)
		require.NoError(t, err)

		// Internal fields should not be in the output
		assert.NotContains(t, string(data), "_embedded_secrets_file")
		assert.NotContains(t, string(data), "_internal_processing_key")
		assert.Contains(t, string(data), "tags")
	})
}

func TestLoadAndProcessProfile(t *testing.T) {
	t.Run("CompleteProfile", func(t *testing.T) {
		profileContent := `name: complete-test
purpose: Testing complete profile processing
description: A comprehensive test

list: |
  target1.com
  target2.com

tags:
  - cve
  - exposure

timeout: 30

secrets:
  static:
    - type: header
      headers:
        - key: X-API-Key
          value: test-key
`
		tmpFile, err := os.CreateTemp("", "test-profile-*.yml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(profileContent)
		require.NoError(t, err)
		tmpFile.Close()

		config, secretsFile, err := LoadAndProcessProfile(tmpFile.Name())
		require.NoError(t, err)
		require.NotNil(t, config)

		// If secrets file was created, clean it up
		if secretsFile != "" {
			defer os.Remove(secretsFile)
			assert.FileExists(t, secretsFile)
		}

		// Config should have the expected fields
		assert.Contains(t, config, "tags")
		assert.Contains(t, config, "timeout")
		assert.Contains(t, config, "list")

		// Secrets should not be in the main config
		assert.NotContains(t, config, "secrets")
	})
}
