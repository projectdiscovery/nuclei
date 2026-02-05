package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestPreprocessConfigFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "nuclei-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Define a sample config with extra fields and secrets
	configContent := `
name: test-profile
description: A test profile
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: Authorization
          value: Bearer token
other-flag: value
`
	configPath := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Run preprocessConfigFile
	newConfigPath, err := preprocessConfigFile(configPath)
	require.NoError(t, err)
	defer os.Remove(newConfigPath)

	// Read the new config file
	newContent, err := os.ReadFile(newConfigPath)
	require.NoError(t, err)

	var data map[string]interface{}
	err = yaml.Unmarshal(newContent, &data)
	require.NoError(t, err)

	// Assertions
	// 1. Check extra fields are removed
	_, hasName := data["name"]
	require.False(t, hasName, "name field should be removed")
	_, hasDesc := data["description"]
	require.False(t, hasDesc, "description field should be removed")

	// 2. Check other flags are preserved
	val, hasOther := data["other-flag"]
	require.True(t, hasOther, "other-flag should be preserved")
	require.Equal(t, "value", val)

	// 3. Check secrets are transformed
	_, hasSecrets := data["secrets"]
	require.False(t, hasSecrets, "secrets field should be removed/replaced")

	secretFiles, hasSecretFile := data["secret-file"]
	require.True(t, hasSecretFile, "secret-file key should be present")
	
	filesSlice, ok := secretFiles.([]interface{})
	require.True(t, ok, "secret-file should be a slice")
	require.NotEmpty(t, filesSlice, "secret-file slice should not be empty")

	// Verify the content of the generated secret file
	generatedSecretPath := filesSlice[0].(string)
	defer os.Remove(generatedSecretPath)
	
	secretContent, err := os.ReadFile(generatedSecretPath)
	require.NoError(t, err)
	
	var secretData map[string]interface{}
	err = yaml.Unmarshal(secretContent, &secretData)
	require.NoError(t, err)
	
	_, hasStatic := secretData["static"]
	require.True(t, hasStatic, "generated secret file should contain static secrets")
}
