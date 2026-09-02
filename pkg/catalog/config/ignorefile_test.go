package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadIgnoreFileAllowsMissingOrInvalidActiveFile(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	if ignore := ReadIgnoreFile(); len(ignore.Tags) != 0 || len(ignore.Files) != 0 {
		t.Fatalf("missing ignore file = %+v, want empty", ignore)
	}

	if err := os.WriteFile(filepath.Join(root, NucleiIgnoreFileName), []byte("tags: ["), 0o600); err != nil {
		t.Fatalf("write invalid ignore file: %v", err)
	}
	if ignore := ReadIgnoreFile(); len(ignore.Tags) != 0 || len(ignore.Files) != 0 {
		t.Fatalf("invalid ignore file = %+v, want empty", ignore)
	}

	if err := os.WriteFile(filepath.Join(root, NucleiIgnoreFileName), []byte("tags: [weak]\nfiles: [blocked.yaml]\n"), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	ignore := ReadIgnoreFile()
	if len(ignore.Tags) != 1 || ignore.Tags[0] != "weak" {
		t.Fatalf("ignore tags = %v, want [weak]", ignore.Tags)
	}
	if len(ignore.Files) != 1 || ignore.Files[0] != "blocked.yaml" {
		t.Fatalf("ignore files = %v, want [blocked.yaml]", ignore.Files)
	}
}

func TestSetTemplatesDirDoesNotCopyLegacyIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	legacyPath := filepath.Join(configDir, NucleiIgnoreFileName)
	writeTestFile(t, legacyPath, []byte("tags: [legacy]\n"), 0o600)

	root := filepath.Join(dir, "active")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create active root: %v", err)
	}
	cfg := &Config{configDir: configDir}
	cfg.SetTemplatesDir(root)
	if _, err := os.Stat(cfg.GetActiveIgnoreFilePath()); !os.IsNotExist(err) {
		t.Fatalf("legacy ignore file was copied into active root: %v", err)
	}
}
