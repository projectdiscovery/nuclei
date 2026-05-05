package filepathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsPathWithinDirectory(t *testing.T) {
	baseDir := t.TempDir()
	childFile := filepath.Join(baseDir, "nested", "child.txt")
	if err := os.MkdirAll(filepath.Dir(childFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !IsPathWithinDirectory(childFile, baseDir) {
		t.Fatalf("expected %q to be inside %q", childFile, baseDir)
	}

	outsideFile := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsPathWithinDirectory(outsideFile, baseDir) {
		t.Fatalf("expected %q to be outside %q", outsideFile, baseDir)
	}
}

func TestIsPathWithinDirectoryWithSymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}

	realDir := t.TempDir()
	aliasDir := filepath.Join(t.TempDir(), "templates-link")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	childFile := filepath.Join(realDir, "helpers", "allowed.js")
	if err := os.MkdirAll(filepath.Dir(childFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childFile, []byte("module.exports = {};"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !IsPathWithinDirectory(childFile, aliasDir) {
		t.Fatalf("expected %q to be inside symlinked dir %q", childFile, aliasDir)
	}
}
