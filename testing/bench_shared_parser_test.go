package testing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// BenchmarkSharedParser benchmarks LoadAllTemplates with and without shared parsed cache.
// It skips if nuclei-templates directory is not present to avoid fetching during benchmarks.
func BenchmarkSharedParser(b *testing.B) {
	templatesDir := config.DefaultConfig.TemplatesDirectory
	if fi, err := os.Stat(filepath.Clean(templatesDir)); err != nil || !fi.IsDir() {
		b.Skipf("templates directory not available: %s", templatesDir)
		return
	}

	b.Run("no_shared", func(b *testing.B) {
		_ = os.Unsetenv("NUCLEI_USE_SHARED_PARSER")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ne, err := nuclei.NewNucleiEngineCtx(context.Background())
			if err != nil {
				b.Fatalf("engine error: %v", err)
			}
			if err := ne.LoadAllTemplates(); err != nil {
				b.Fatalf("load templates error: %v", err)
			}
			ne.Close()
		}
	})

	b.Run("shared", func(b *testing.B) {
		_ = os.Setenv("NUCLEI_USE_SHARED_PARSER", "1")
		b.Cleanup(func() { _ = os.Unsetenv("NUCLEI_USE_SHARED_PARSER") })
		// warm up shared cache once
		warm, err := nuclei.NewNucleiEngineCtx(context.Background())
		if err != nil {
			b.Fatalf("warm engine error: %v", err)
		}
		if err := warm.LoadAllTemplates(); err != nil {
			b.Fatalf("warm load error: %v", err)
		}
		warm.Close()

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ne, err := nuclei.NewNucleiEngineCtx(context.Background())
			if err != nil {
				b.Fatalf("engine error: %v", err)
			}
			if err := ne.LoadAllTemplates(); err != nil {
				b.Fatalf("load templates error: %v", err)
			}
			ne.Close()
		}
	})
}
