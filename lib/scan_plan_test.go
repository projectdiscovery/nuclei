package nuclei_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestScanPlanOptions(t *testing.T) {
	ne, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.DisableUpdateCheck(),
		nuclei.EnableStrictProbe(),
		nuclei.EnableTechFilter(),
		nuclei.EnableResponseCache(),
	)
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.True(t, opts.StrictProbe)
	require.True(t, opts.TechFilter)
	require.True(t, opts.ResponseCache)
}

// sdkCacheTemplates writes two templates that both GET /same. The second also
// GETs /other, so request clustering cannot merge them into one request.
func sdkCacheTemplates(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	a := `id: sdk-cache-a
info:
  name: SDK Cache A
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/same"
    matchers:
      - type: word
        words:
          - "cached-body"
`
	b := `id: sdk-cache-b
info:
  name: SDK Cache B
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/same"
      - "{{BaseURL}}/other"
    matchers:
      - type: word
        words:
          - "cached-body"
`
	pa, pb := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	require.NoError(t, os.WriteFile(pa, []byte(a), 0o600))
	require.NoError(t, os.WriteFile(pb, []byte(b), 0o600))
	return []string{pa, pb}
}

// With the SDK options for the scan plan set, both templates still run and
// match, and the response cache sends /same once. Without them it is sent
// twice.
func TestSDKScanPlanAndResponseCache(t *testing.T) {
	var sameHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			sameHits.Add(1)
			time.Sleep(200 * time.Millisecond)
		}
		_, _ = w.Write([]byte("cached-body"))
	}))
	defer ts.Close()
	tpls := sdkCacheTemplates(t)

	run := func(extra ...nuclei.NucleiSDKOptions) map[string]bool {
		sameHits.Store(0)
		opts := append([]nuclei.NucleiSDKOptions{
			nuclei.DisableUpdateCheck(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: tpls}),
		}, extra...)
		ne, err := nuclei.NewNucleiEngineCtx(context.Background(), opts...)
		require.NoError(t, err)
		defer ne.Close()
		ne.Options().RestrictLocalNetworkAccess = false
		ne.Options().Retries = 0
		ne.LoadTargets([]string{ts.URL}, false)

		var mu sync.Mutex
		matched := map[string]bool{}
		require.NoError(t, ne.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
			mu.Lock()
			defer mu.Unlock()
			matched[event.TemplateID] = true
		}))
		return matched
	}

	matched := run(nuclei.EnableResponseCache(), nuclei.EnableStrictProbe(), nuclei.EnableTechFilter())
	require.Equal(t, map[string]bool{"sdk-cache-a": true, "sdk-cache-b": true}, matched)
	require.Equal(t, int32(1), sameHits.Load(), "the response cache must send /same once")

	matched = run()
	require.Equal(t, map[string]bool{"sdk-cache-a": true, "sdk-cache-b": true}, matched)
	require.Equal(t, int32(2), sameHits.Load(), "without the cache /same is sent by each template")
}
