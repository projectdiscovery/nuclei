package nuclei_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestThreadSafeCachedFlowPreservesPrecondition(t *testing.T) {
	for _, positive := range []bool{false, true} {
		name := "negative"
		if positive {
			name = "positive"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "flow.yaml")
			require.NoError(t, os.WriteFile(path, []byte(`id: cached-flow
info:
  name: Cached flow
  author: pdteam
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path: ["{{BaseURL}}/precondition"]
    matchers:
      - type: status
        status: [200]
        internal: true
  - method: GET
    path: ["{{BaseURL}}/check"]
    matchers:
      - type: status
        status: [404]
`), 0o600))
			var checks, findings atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/check" {
					checks.Add(1)
				}
				if positive && r.URL.Path == "/precondition" {
					w.WriteHeader(200)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			engine, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), nuclei.DisableUpdateCheck())
			require.NoError(t, err)
			defer engine.Close()
			engine.GlobalResultCallback(func(*output.ResultEvent) { findings.Add(1) })
			for call := int64(1); call <= 3; call++ {
				require.NoError(t, engine.ExecuteNucleiWithOptsCtx(context.Background(), []string{server.URL}, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{path}})))
				expected := int64(0)
				if positive {
					expected = call
				}
				require.Equal(t, expected, checks.Load(), "check requests after call %d", call)
				require.Equal(t, expected, findings.Load(), "findings after call %d", call)
			}
		})
	}
}
