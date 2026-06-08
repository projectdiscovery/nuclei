package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/stretchr/testify/require"
)

// secretsYAML is a real nuclei auth secrets file with a header+cookie secret
// scoped to app.example.com (and a regex domain), used to exercise the headless
// auth-fusion seam through the production FileAuthProvider rather than a mock.
const secretsYAML = `id: headless-auth-e2e
info:
  name: headless auth e2e
  author: pdteam
  severity: info
static:
  - type: header
    domains:
      - app.example.com
    domains-regex:
      - "^api\\.example\\.com$"
    headers:
      - key: X-Api-Key
        value: s3cr3t-key
  - type: cookie
    domains:
      - app.example.com
    cookies:
      - key: session
        value: abc123
`

func writeSecretsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte(secretsYAML), 0o600))
	return path
}

// TestHeadlessAuthFusion_RealProvider_E2E builds a real file-based auth provider
// and drives the headless fusion seam (resolveAuthMaterial) end to end: it
// verifies that the provider's domain-scoped secrets are correctly materialized
// into the extra headers and cookies the browser would receive, and that
// non-matching domains yield nothing. This is the browser-free core of the
// headless+auth integration and runs reliably in CI.
func TestHeadlessAuthFusion_RealProvider_E2E(t *testing.T) {
	provider, err := authprovider.NewFileAuthProvider(writeSecretsFile(t), nil, nil)
	require.NoError(t, err)

	t.Run("matching domain materializes header and cookie", func(t *testing.T) {
		headers, cookies := resolveAuthMaterial(provider, mustParseURL(t, "https://app.example.com/dashboard"))

		headerMap := pairsToMap(t, headers)
		require.Equal(t, "s3cr3t-key", headerMap["X-Api-Key"])
		_, hasCookieHeader := headerMap["Cookie"]
		require.False(t, hasCookieHeader, "Cookie must be delivered as a browser cookie, not an extra header")

		require.Len(t, cookies, 1)
		require.Equal(t, "session", cookies[0].Name)
		require.Equal(t, "abc123", cookies[0].Value)
	})

	t.Run("regex domain matches", func(t *testing.T) {
		headers, _ := resolveAuthMaterial(provider, mustParseURL(t, "https://api.example.com/v1"))
		headerMap := pairsToMap(t, headers)
		require.Equal(t, "s3cr3t-key", headerMap["X-Api-Key"], "regex-scoped secret must apply to api.example.com")
	})

	t.Run("non-matching domain yields nothing", func(t *testing.T) {
		headers, cookies := resolveAuthMaterial(provider, mustParseURL(t, "https://evil.example.org/"))
		require.Empty(t, headers, "no credentials should be sent to an out-of-scope domain")
		require.Empty(t, cookies, "no cookies should be sent to an out-of-scope domain")
	})
}
