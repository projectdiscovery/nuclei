package authx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractSecretsFromProfile_NoSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	profile := filepath.Join(tmpDir, "profile.yaml")
	err := os.WriteFile(profile, []byte(`
name: test-profile
purpose: testing
exclude-tags:
  - dos
  - fuzz
template-concurrency: 5
`), 0644)
	require.NoError(t, err)

	result, err := ExtractSecretsFromProfile(profile)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestExtractSecretsFromProfile_WithStaticSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	profile := filepath.Join(tmpDir, "profile.yaml")
	err := os.WriteFile(profile, []byte(`
name: test-profile
purpose: testing
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: x-api-key
          value: test-secret-value
`), 0644)
	require.NoError(t, err)

	tmpFile, err := ExtractSecretsFromProfile(profile)
	require.NoError(t, err)
	require.NotEmpty(t, tmpFile)
	defer os.Remove(tmpFile)

	// Verify the temp file contains valid secrets YAML
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	require.Contains(t, string(data), "static")
	require.Contains(t, string(data), "x-api-key")

	// Verify it can be parsed as a valid Authx struct
	auth, err := GetAuthDataFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, auth.Secrets, 1)
	require.Equal(t, "header", auth.Secrets[0].Type)
	require.Contains(t, auth.Secrets[0].Domains, "api.example.com")
}

func TestExtractSecretsFromProfile_WithDynamicSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	profile := filepath.Join(tmpDir, "profile.yaml")
	err := os.WriteFile(profile, []byte(`
name: test-profile
secrets:
  dynamic:
    - template: custom-oauth-flow.yaml
      variables:
        - name: username
          value: testuser
      secrets:
        - type: cookie
          domains:
            - .*.example.com
          cookies:
            - key: session
              value: "{{token}}"
`), 0644)
	require.NoError(t, err)

	tmpFile, err := ExtractSecretsFromProfile(profile)
	require.NoError(t, err)
	require.NotEmpty(t, tmpFile)
	defer os.Remove(tmpFile)

	// Verify it can be parsed as a valid Authx struct
	auth, err := GetAuthDataFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, auth.Dynamic, 1)
	require.Equal(t, "custom-oauth-flow.yaml", auth.Dynamic[0].TemplatePath)
	require.Len(t, auth.Dynamic[0].Variables, 1)
	require.Equal(t, "testuser", auth.Dynamic[0].Variables[0].Value)
}

func TestExtractSecretsFromProfile_MixedWithFlags(t *testing.T) {
	tmpDir := t.TempDir()
	profile := filepath.Join(tmpDir, "profile.yaml")
	err := os.WriteFile(profile, []byte(`
name: projectdiscovery-scan
purpose: Config File for Scanning
description: single config file with all config and auth
type:
  - http
  - tcp
exclude-tags:
  - dos
  - fuzz
secrets:
  static:
    - type: bearer
      domains:
        - api.example.com
      token: my-bearer-token
`), 0644)
	require.NoError(t, err)

	tmpFile, err := ExtractSecretsFromProfile(profile)
	require.NoError(t, err)
	require.NotEmpty(t, tmpFile)
	defer os.Remove(tmpFile)

	auth, err := GetAuthDataFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, auth.Secrets, 1)
	require.Equal(t, "bearer", auth.Secrets[0].Type)
	require.Equal(t, "my-bearer-token", auth.Secrets[0].Token)
}

func TestExtractSecretsFromProfile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	profile := filepath.Join(tmpDir, "profile.yaml")
	err := os.WriteFile(profile, []byte(`invalid: yaml: content:`), 0644)
	require.NoError(t, err)

	_, err = ExtractSecretsFromProfile(profile)
	require.Error(t, err)
}

func TestExtractSecretsFromProfile_NonexistentFile(t *testing.T) {
	_, err := ExtractSecretsFromProfile("/nonexistent/profile.yaml")
	require.Error(t, err)
}
