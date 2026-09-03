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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecuteNucleiWithOptsCtxKeepsBaseExcludeTags covers the case where a
// per-execution filter that names only Tags used to clear the engine's
// ExcludeTags — which carry the .nuclei-ignore deny-list installed at
// construction — letting templates tagged dos (and local, fuzz, bruteforce,
// txt-service) execute against the target.
//
// The engine's construction-time ExcludeTags stand in for that deny-list, and
// the per-execution filter deliberately asks for the excluded tag: exclusion
// must still win, because IncludeTags is the documented way to override it.
func TestExecuteNucleiWithOptsCtxKeepsBaseExcludeTags(t *testing.T) {
	templatePath := writeSDKDosTaggedTemplate(t)

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("token-dos"))
	}))
	t.Cleanup(srv.Close)

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ExcludeTags: []string{"dos"}}),
	)
	require.NoError(t, err, "could not create thread-safe nuclei engine")
	t.Cleanup(ne.Close)

	var matches atomic.Int64
	ne.GlobalResultCallback(func(*output.ResultEvent) { matches.Add(1) })

	err = ne.ExecuteNucleiWithOptsCtx(context.Background(), []string{srv.URL},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"dos"}}),
	)

	require.ErrorIs(t, err, nuclei.ErrNoTemplatesAvailable,
		"the dos-tagged template must stay excluded, leaving nothing to run")
	assert.Zero(t, matches.Load(), "an excluded template must not report results")
	assert.False(t, reached.Load(), "an excluded template must not reach the target")
}

// TestExecuteNucleiWithOptsCtxHonoursIncludeTags is the other half of the
// contract: restoring the baseline exclusions must not break the documented
// per-tag override, or callers lose the only way to run an ignored template.
func TestExecuteNucleiWithOptsCtxHonoursIncludeTags(t *testing.T) {
	templatePath := writeSDKDosTaggedTemplate(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("token-dos"))
	}))
	t.Cleanup(srv.Close)

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ExcludeTags: []string{"dos"}}),
	)
	require.NoError(t, err, "could not create thread-safe nuclei engine")
	t.Cleanup(ne.Close)

	var matches atomic.Int64
	ne.GlobalResultCallback(func(*output.ResultEvent) { matches.Add(1) })

	err = ne.ExecuteNucleiWithOptsCtx(context.Background(), []string{srv.URL},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{IncludeTags: []string{"dos"}}),
	)

	require.NoError(t, err)
	assert.NotZero(t, matches.Load(), "IncludeTags should still override the exclusion")
}

func writeSDKDosTaggedTemplate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sdk-dos-tagged.yaml")
	content := `id: sdk-dos-tagged
info:
  name: SDK dos tagged
  author: nuclei-sdk-test
  severity: info
  tags: dos
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "token-"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
