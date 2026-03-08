package authx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretsUnmarshal(t *testing.T) {
	loc := "testData/example-auth.yaml"
	data, err := GetAuthDataFromFile(loc)
	require.Nil(t, err, "could not read secrets file")
	require.NotNil(t, data, "could not read secrets file")
	for _, s := range data.Secrets {
		require.Nil(t, s.Validate(), "could not validate secret")
	}
	for _, d := range data.Dynamic {
		require.Nil(t, d.Validate(), "could not validate dynamic")
	}
}

func TestExtractSecretsYAMLFromConfig(t *testing.T) {
	t.Run("extracts secrets section from config YAML", func(t *testing.T) {
		configYAML := []byte(`
name: test-profile
purpose: testing
tags:
  - cve
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: x-api-key
          value: test-key
  dynamic:
    - template: /path/to/auth.yaml
      variables:
        - name: username
          value: admin
      type: Cookie
      domains:
        - example.com
      cookies:
        - raw: "{{session-cookie}}"
`)
		secretsYAML, err := ExtractSecretsYAMLFromConfig(configYAML)
		require.NoError(t, err, "should extract secrets section")
		require.NotEmpty(t, secretsYAML, "secrets YAML should not be empty")

		// Verify the extracted YAML can be parsed as auth data
		authData, err := GetAuthDataFromYAML(secretsYAML)
		require.NoError(t, err, "should parse extracted secrets YAML")
		require.NotNil(t, authData, "auth data should not be nil")
		require.Len(t, authData.Secrets, 1, "should have 1 static secret")
		require.Equal(t, "header", authData.Secrets[0].Type)
		require.Equal(t, []string{"api.example.com"}, authData.Secrets[0].Domains)
		require.Len(t, authData.Secrets[0].Headers, 1)
		require.Equal(t, "x-api-key", authData.Secrets[0].Headers[0].Key)
		require.Len(t, authData.Dynamic, 1, "should have 1 dynamic secret")
		require.Equal(t, "/path/to/auth.yaml", authData.Dynamic[0].TemplatePath)
	})

	t.Run("returns error when no secrets section", func(t *testing.T) {
		configYAML := []byte(`
name: test-profile
tags:
  - cve
timeout: 30
`)
		_, err := ExtractSecretsYAMLFromConfig(configYAML)
		require.Error(t, err, "should error when no secrets section")
		require.Contains(t, err.Error(), "no secrets section")
	})

	t.Run("returns error for invalid YAML", func(t *testing.T) {
		configYAML := []byte(`invalid: yaml: [`)
		_, err := ExtractSecretsYAMLFromConfig(configYAML)
		require.Error(t, err, "should error on invalid YAML")
	})
}

func TestExtractAuthDataFromConfig(t *testing.T) {
	configYAML := []byte(`
name: test-profile
purpose: scan with auth
secrets:
  static:
    - type: BearerToken
      domains:
        - api.example.com
      token: my-bearer-token
`)
	authData, err := ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err, "should extract auth data from config")
	require.NotNil(t, authData, "auth data should not be nil")
	require.Len(t, authData.Secrets, 1, "should have 1 secret")
	require.Equal(t, "BearerToken", authData.Secrets[0].Type)
	require.Equal(t, "my-bearer-token", authData.Secrets[0].Token)
	require.NoError(t, authData.Secrets[0].Validate(), "secret should be valid")
}

func TestConfigWithExtraFieldsDoesNotAffectSecrets(t *testing.T) {
	// Verify that extra fields like id, name, purpose, description
	// in the config YAML do not interfere with secrets extraction
	configYAML := []byte(`
id: my-profile-id
name: My Profile
purpose: Testing extra fields
description: This profile has metadata and secrets
custom-field: some-value
another-extra: 123
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: Authorization
          value: Bearer test123
`)
	authData, err := ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err, "extra fields should not interfere with secrets extraction")
	require.NotNil(t, authData)
	require.Len(t, authData.Secrets, 1)
	require.Equal(t, "header", authData.Secrets[0].Type)
	require.NoError(t, authData.Secrets[0].Validate())
}
