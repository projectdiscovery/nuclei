package utils

import (
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestTemplatePathURLUsesTemplateDirBoundaries(t *testing.T) {
	templatesDir := filepath.Join(t.TempDir(), "nuclei-templates")

	oldTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})

	path, _ := TemplatePathURL(filepath.Join(templatesDir, "http", "test.yaml"), "test", "")
	if path != filepath.Join("http", "test.yaml") {
		t.Fatalf("expected relative template path, got %q", path)
	}

	path, _ = TemplatePathURL(filepath.Join(templatesDir+"-evil", "test.yaml"), "test", "")
	if path != "" {
		t.Fatalf("expected sibling prefix path not to be relativized, got %q", path)
	}
}
