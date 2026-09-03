package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func setActiveIgnoreFileRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	cfg := DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)
	return root
}

func TestReadIgnoreFileReportsMissingActiveFile(t *testing.T) {
	root := setActiveIgnoreFileRoot(t)
	path := filepath.Join(root, NucleiIgnoreFileName)

	ignore, err := ReadIgnoreFile()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read missing ignore file error = %v, want os.ErrNotExist", err)
	}
	if len(ignore.Tags) != 0 || len(ignore.Files) != 0 {
		t.Fatalf("missing ignore file = %+v, want empty", ignore)
	}
	if message := err.Error(); !strings.Contains(message, strconv.Quote(path)) || !strings.Contains(message, "error opening") {
		t.Fatalf("missing ignore file error = %q, want open failure and active path", message)
	}
}

func TestReadIgnoreFileRejectsCorruptActiveFile(t *testing.T) {
	root := setActiveIgnoreFileRoot(t)
	path := filepath.Join(root, NucleiIgnoreFileName)

	if err := os.WriteFile(path, []byte("tags: ["), 0o600); err != nil {
		t.Fatalf("write invalid ignore file: %v", err)
	}
	ignore, err := ReadIgnoreFile()
	if err == nil {
		t.Fatalf("read corrupt ignore file = %+v, want error", ignore)
	}
	if message := err.Error(); !strings.Contains(message, strconv.Quote(path)) || !strings.Contains(message, "error parsing") {
		t.Fatalf("corrupt ignore file error = %q, want parse failure and active path", message)
	}
}

func TestReadIgnoreFileRejectsMalformedTrailingDocument(t *testing.T) {
	root := setActiveIgnoreFileRoot(t)
	path := filepath.Join(root, NucleiIgnoreFileName)

	if err := os.WriteFile(path, []byte("tags: [weak]\n---\ntags: ["), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	ignore, err := ReadIgnoreFile()
	if err == nil {
		t.Fatalf("read ignore file = %+v, want trailing parse error", ignore)
	}
	if len(ignore.Tags) != 0 || len(ignore.Files) != 0 {
		t.Fatalf("ignore file after trailing parse error = %+v, want empty", ignore)
	}
	if message := err.Error(); !strings.Contains(message, strconv.Quote(path)) || !strings.Contains(message, "error parsing") {
		t.Fatalf("trailing parse error = %q, want parse failure and active path", message)
	}
}

func TestReadIgnoreFileRejectsAdditionalDocument(t *testing.T) {
	root := setActiveIgnoreFileRoot(t)
	path := filepath.Join(root, NucleiIgnoreFileName)

	if err := os.WriteFile(path, []byte("tags: [weak]\n---\nfiles: [blocked.yaml]\n"), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	ignore, err := ReadIgnoreFile()
	if err == nil {
		t.Fatalf("read ignore file = %+v, want multiple-document error", ignore)
	}
	if len(ignore.Tags) != 0 || len(ignore.Files) != 0 {
		t.Fatalf("ignore file with additional document = %+v, want empty", ignore)
	}
	if message := err.Error(); !strings.Contains(message, strconv.Quote(path)) || !strings.Contains(message, "multiple YAML documents") {
		t.Fatalf("multiple-document error = %q, want active path and document count failure", message)
	}
}

func TestReadIgnoreFileParsesActiveFile(t *testing.T) {
	root := setActiveIgnoreFileRoot(t)

	if err := os.WriteFile(filepath.Join(root, NucleiIgnoreFileName), []byte("tags: [weak]\nfiles: [blocked.yaml]\n"), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	ignore, err := ReadIgnoreFile()
	if err != nil {
		t.Fatalf("read ignore file: %v", err)
	}
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
