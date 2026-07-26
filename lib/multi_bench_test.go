package nuclei

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
)

func BenchmarkExecuteNucleiWithOptsCtx(b *testing.B) {
	templatePath := filepath.Join(b.TempDir(), "benchmark.yaml")
	err := os.WriteFile(templatePath, []byte(`id: benchmark-execute-nuclei-with-opts-ctx

info:
  name: Benchmark ExecuteNucleiWithOptsCtx
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 418
`), 0o600)
	if err != nil {
		b.Fatalf("could not write benchmark template: %s", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	b.Cleanup(server.Close)

	_, err = index.NewIndex(b.TempDir())
	if err != nil {
		b.Fatalf("could not create benchmark metadata index: %s", err)
	}

	engine, err := NewThreadSafeNucleiEngineCtx(
		b.Context(),
		DisableUpdateCheck(),
		WithTemplatesOrWorkflows(TemplateSources{Templates: []string{templatePath}}),
	)
	if err != nil {
		b.Fatalf("could not create thread-safe nuclei engine: %s", err)
	}
	b.Cleanup(engine.Close)

	// Keep benchmark metadata isolated from the user's persistent cache.
	// engine.eng.metadataIndexOnce.Do(func() {
	// 	engine.eng.metadataIndex = metadataIndex
	// })

	targets := []string{server.URL}
	if err := engine.ExecuteNucleiWithOptsCtx(b.Context(), targets); err != nil {
		b.Fatalf("could not warm up nuclei execution: %s", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := engine.ExecuteNucleiWithOptsCtx(b.Context(), targets); err != nil {
			b.Fatalf("could not execute nuclei: %s", err)
		}
	}
}
