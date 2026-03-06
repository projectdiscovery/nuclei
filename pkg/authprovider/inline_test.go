package authprovider_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

// TestInlineSecretsEndToEnd spins up a real HTTP test server that echoes back
// the headers it receives. It then:
//  1. Builds an auth provider from a config YAML with an inline secrets block
//  2. Looks up the auth strategy for the test server's URL
//  3. Applies the strategy to a real *http.Request
//  4. Sends the request and verifies the server received the injected header
func TestInlineSecretsEndToEnd(t *testing.T) {
	const headerKey = "X-Api-Token"
	const headerVal = "inline-secret-value"

	// real HTTP server that asserts the header is present
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(headerKey)
		if got != headerVal {
			http.Error(w, "missing or wrong header: "+got, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	tsHost := tsURL.Host // e.g. "127.0.0.1:PORT"

	// config YAML with inline secrets targeting the test server host
	configYAML := []byte(`
name: e2e-test
purpose: end-to-end test for inline secrets

secrets:
  static:
    - type: Header
      domains:
        - ` + tsHost + `
      headers:
        - key: ` + headerKey + `
          value: ` + headerVal + `
`)

	// --- extract secrets from config ---
	authData, err := authx.ExtractAuthDataFromConfig(configYAML)
	require.NoError(t, err)
	require.NotNil(t, authData)

	// --- build provider via NewInlineAuthProvider ---
	provider, err := authprovider.NewInlineAuthProvider(authData, nil)
	require.NoError(t, err)

	// --- lookup strategy for the test server URL ---
	strategies := provider.LookupURL(tsURL)
	require.NotEmpty(t, strategies, "expected a strategy for %s", tsHost)

	// --- build request and apply strategy ---
	req, err := http.NewRequest("GET", ts.URL+"/test", nil)
	require.NoError(t, err)

	for _, s := range strategies {
		s.Apply(req)
	}

	// --- send the real request ---
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"server rejected request — inline header was not applied correctly")
}

// TestInlineSecretsViaAuthProviderOptions verifies the full NewAuthProvider
// path with InlineSecrets populated (same path used by runner/sdk).
func TestInlineSecretsViaAuthProviderOptions(t *testing.T) {
	const headerKey = "Authorization"
	const headerVal = "Bearer test-token-xyz"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerKey) != headerVal {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	tsHost := tsURL.Host

	authData := &authx.Authx{
		Secrets: []authx.Secret{
			{
				Type:    "Header",
				Domains: []string{tsHost},
				Headers: []authx.KV{
					{Key: headerKey, Value: headerVal},
				},
			},
		},
	}

	opts := &authprovider.AuthProviderOptions{
		InlineSecrets: []*authx.Authx{authData},
	}
	provider, err := authprovider.NewAuthProvider(opts)
	require.NoError(t, err)

	strategies := provider.LookupURL(tsURL)
	require.NotEmpty(t, strategies)

	req, err := http.NewRequest("GET", ts.URL+"/api", nil)
	require.NoError(t, err)
	for _, s := range strategies {
		s.Apply(req)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"server rejected request — Authorization header was not applied")
}
