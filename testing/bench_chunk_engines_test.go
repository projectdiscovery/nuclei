package testing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// BenchmarkChunkEngines simulates the aurora agent pattern where multiple chunks
// create engines against the same template set. It compares shared vs non-shared parser.
// We only load templates (no scan execution) to stress parsing/compile memory like the loader path.
func BenchmarkChunkEngines(b *testing.B) {
	templatesDir := config.DefaultConfig.TemplatesDirectory
	if fi, err := os.Stat(filepath.Clean(templatesDir)); err != nil || !fi.IsDir() {
		b.Skipf("templates directory not available: %s", templatesDir)
		return
	}

	// number of synthetic "chunks" (engines) to simulate
	const chunks = 20

	b.Run("no_shared", func(b *testing.B) {
		_ = os.Unsetenv("NUCLEI_USE_SHARED_PARSER")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// create engines like separate chunks would
			engines := make([]*nuclei.NucleiEngine, 0, chunks)
			for c := 0; c < chunks; c++ {
				ne, err := nuclei.NewNucleiEngineCtx(context.Background())
				if err != nil {
					b.Fatalf("engine error: %v", err)
				}
				engines = append(engines, ne)
			}
			// load templates on each engine (same set)
			for _, ne := range engines {
				if err := ne.LoadAllTemplates(); err != nil {
					b.Fatalf("load templates error: %v", err)
				}
			}
			for _, ne := range engines {
				ne.Close()
			}
		}
	})

	b.Run("shared", func(b *testing.B) {
		_ = os.Setenv("NUCLEI_USE_SHARED_PARSER", "1")
		b.Cleanup(func() { _ = os.Unsetenv("NUCLEI_USE_SHARED_PARSER") })
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			engines := make([]*nuclei.NucleiEngine, 0, chunks)
			for c := 0; c < chunks; c++ {
				ne, err := nuclei.NewNucleiEngineCtx(context.Background())
				if err != nil {
					b.Fatalf("engine error: %v", err)
				}
				engines = append(engines, ne)
			}
			for _, ne := range engines {
				if err := ne.LoadAllTemplates(); err != nil {
					b.Fatalf("load templates error: %v", err)
				}
			}
			for _, ne := range engines {
				ne.Close()
			}
		}
	})
}
