package nuclei_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestThreadSafeWithResultCallbackIsolation(t *testing.T) {
	templatePath := writeSDKMatchTemplate(t)

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("token-A-unique"))
	}))
	t.Cleanup(srvA.Close)

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("token-B-unique"))
	}))
	t.Cleanup(srvB.Close)

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background())
	require.NoError(t, err)
	t.Cleanup(ne.Close)

	var (
		mu          sync.Mutex
		callbackA   []string
		callbackB   []string
		globalURLs  []string
		globalCount int
		errA, errB  error
	)

	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		globalCount++
		globalURLs = append(globalURLs, eventMatchedURL(event))
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errA = ne.ExecuteNucleiWithOptsCtx(context.Background(), []string{srvA.URL},
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"sdk-callback-match"}}),
			nuclei.WithResultCallback(func(event *output.ResultEvent) {
				mu.Lock()
				defer mu.Unlock()
				callbackA = append(callbackA, eventMatchedURL(event))
			}),
		)
	}()

	go func() {
		defer wg.Done()
		errB = ne.ExecuteNucleiWithOptsCtx(context.Background(), []string{srvB.URL},
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"sdk-callback-match"}}),
			nuclei.WithResultCallback(func(event *output.ResultEvent) {
				mu.Lock()
				defer mu.Unlock()
				callbackB = append(callbackB, eventMatchedURL(event))
			}),
		)
	}()

	wg.Wait()

	require.NoError(t, errA)
	require.NoError(t, errB)

	mu.Lock()
	defer mu.Unlock()

	require.NotEmpty(t, callbackA, "per-call callback A should receive results")
	require.NotEmpty(t, callbackB, "per-call callback B should receive results")
	for _, matched := range callbackA {
		require.Contains(t, matched, srvA.URL, "callback A must only see server A")
		require.NotContains(t, matched, srvB.URL, "callback A must not see server B")
	}
	for _, matched := range callbackB {
		require.Contains(t, matched, srvB.URL, "callback B must only see server B")
		require.NotContains(t, matched, srvA.URL, "callback B must not see server A")
	}

	// Global callback still sees both executions (no regression).
	require.GreaterOrEqual(t, globalCount, 2)
	require.NotEmpty(t, globalURLs)
}

func TestThreadSafeGlobalCallbackWithoutPerCallStillWorks(t *testing.T) {
	templatePath := writeSDKMatchTemplate(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("token-A-unique"))
	}))
	t.Cleanup(srv.Close)

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background())
	require.NoError(t, err)
	t.Cleanup(ne.Close)

	var got int
	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		got++
	})

	err = ne.ExecuteNucleiWithOptsCtx(context.Background(), []string{srv.URL},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"sdk-callback-match"}}),
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, got, 1, "global callback should still receive results without WithResultCallback")
}

func TestWithResultCallbackNilIsNoop(t *testing.T) {
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), nuclei.WithResultCallback(nil))
	require.NoError(t, err)
	ne.Close()
}

func writeSDKMatchTemplate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sdk-callback-match.yaml")
	content := `id: sdk-callback-match
info:
  name: SDK callback match
  author: nuclei-sdk-test
  severity: info
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

// eventMatchedURL prefers Matched/URL over Host (Host omits the port).
func eventMatchedURL(event *output.ResultEvent) string {
	if event == nil {
		return ""
	}
	if event.Matched != "" {
		return event.Matched
	}
	if event.URL != "" {
		return event.URL
	}
	return event.Host
}
