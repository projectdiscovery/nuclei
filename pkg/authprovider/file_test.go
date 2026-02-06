package authprovider

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
)

// TestPrefetchSecretsBeforeAuthApply verifies that prefetch resolves dynamic auth before use.
// - t is the testing harness instance.
func TestPrefetchSecretsBeforeAuthApply(t *testing.T) {
	tempDir := t.TempDir()
	secretPath := filepath.Join(tempDir, "secret.yaml")
	secretContent := []byte(`id: test-auth
info:
  name: Test Auth
  author: unit-test
  severity: info
dynamic:
  - template: auth-template.yaml
    variables:
      - key: email
        value: ignored
    secrets:
      - type: Header
        domains:
          - example.com
        headers:
          - key: X-User
            value: "{{email}}"
`)
	require.NoError(t, os.WriteFile(secretPath, secretContent, 0o600))

	var prefetched atomic.Bool
	callback := func(d *authx.Dynamic) error {
		d.Extracted = map[string]interface{}{"email": "engbot@example.com"}
		prefetched.Store(true)
		return nil
	}

	provider, err := NewFileAuthProvider(secretPath, callback)
	require.NoError(t, err)
	require.NoError(t, provider.PreFetchSecrets())
	require.True(t, prefetched.Load())

	strategies := provider.LookupAddr("example.com")
	require.NotEmpty(t, strategies)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	strategies[0].Apply(req)

	require.Equal(t, "engbot@example.com", req.Header.Get("X-User"))
}
