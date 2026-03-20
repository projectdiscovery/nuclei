package authprovider

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

func TestFileAuthProviderDynamicSecretConcurrentAccess(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret.yaml")
	secretData := []byte(`id: test-auth
info:
  name: test
  author: test
  severity: info
dynamic:
  - template: auth-template.yaml
    variables:
      - key: username
        value: test
    type: Header
    domains:
      - example.com
    headers:
      - key: Authorization
        value: "Bearer {{token}}"
`)
	require.NoError(t, os.WriteFile(secretFile, secretData, 0o600))

	var fetchCalls atomic.Int32
	provider, err := NewFileAuthProvider(secretFile, func(dynamic *authx.Dynamic) error {
		fetchCalls.Add(1)
		time.Sleep(75 * time.Millisecond)
		dynamic.Extracted = map[string]interface{}{"token": "session-token"}
		return nil
	})
	require.NoError(t, err)

	const workers = 20
	barrier := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-barrier

			strategies := provider.LookupAddr("example.com")
			if len(strategies) == 0 {
				errs <- fmt.Errorf("no auth strategies found")
				return
			}

			req, reqErr := http.NewRequest(http.MethodGet, "https://example.com", nil)
			if reqErr != nil {
				errs <- reqErr
				return
			}
			for _, strategy := range strategies {
				strategy.Apply(req)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer session-token" {
				errs <- fmt.Errorf("expected Authorization header to be set, got %q", got)
			}
		}()
	}

	close(barrier)
	wg.Wait()
	close(errs)

	for gotErr := range errs {
		require.NoError(t, gotErr)
	}
	require.Equal(t, int32(1), fetchCalls.Load(), "dynamic secret fetch should execute once")
}
