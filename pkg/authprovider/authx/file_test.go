package authx

import (
	"net/http"
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

func TestExtractSecretsFromConfigYAML(t *testing.T) {
	configYAML := []byte(`
name: test-scan
purpose: testing inline secrets

list: |
  example.com
  test.example.com

concurrency: 5

secrets:
  static:
    - type: Header
      domains:
        - example.com
        - test.example.com
      headers:
        - key: X-API-Key
          value: supersecret
`)

	// should extract the secrets block without error
	authData, err := ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err)
	require.NotNil(t, authData, "expected auth data to be extracted")
	require.Len(t, authData.Secrets, 1)
	require.Equal(t, "Header", authData.Secrets[0].Type)
	require.Equal(t, "X-API-Key", authData.Secrets[0].Headers[0].Key)
	require.Equal(t, "supersecret", authData.Secrets[0].Headers[0].Value)
}

func TestExtractSecretsFromConfigNoSecretsKey(t *testing.T) {
	configYAML := []byte(`
name: test-scan
concurrency: 5
type:
  - http
`)
	authData, err := ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err)
	require.Nil(t, authData, "expected nil when no secrets key present")
}

func TestInlineAuthProviderAppliesHeader(t *testing.T) {
	configYAML := []byte(`
secrets:
  static:
    - type: Header
      domains:
        - api.example.com
      headers:
        - key: X-Token
          value: mytoken123
`)
	authData, err := ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err)
	require.NotNil(t, authData)

	// build strategy from inline Authx directly
	strategy := authData.Secrets[0].GetStrategy()
	require.NotNil(t, strategy)

	req, _ := http.NewRequest("GET", "https://api.example.com/v1/test", nil)
	strategy.Apply(req)

	require.Equal(t, "mytoken123", req.Header.Get("X-Token"), "inline secret header must be applied to request")
}

