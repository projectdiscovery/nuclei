package filepathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestIsPathWithinAnyDirectory(t *testing.T) {
	baseDir := t.TempDir()
	otherDir := t.TempDir()
	childFile := filepath.Join(baseDir, "child.txt")
	if err := os.WriteFile(childFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !IsPathWithinAnyDirectory(childFile, "", otherDir, baseDir) {
		t.Fatalf("expected %q to be inside one of the allowed directories", childFile)
	}
	if IsPathWithinAnyDirectory(filepath.Join(t.TempDir(), "outside.txt"), "", otherDir, baseDir) {
		t.Fatal("expected outside path not to be inside allowed directories")
	}
}

// TestIsPathWithinDirectoryRejectsEmptyInputs documents the hard
// fail-closed behaviour of the helper for empty arguments.
//
// filepath.Abs("") returns the process working directory, so a naive
// canonicalization-then-Rel chain would silently treat empty arguments as a
// CWD-relative sandbox: e.g. IsPathWithinDirectory("/etc/passwd", "")
// resolved as "is /etc/passwd inside CWD?" and IsPathWithinDirectory("",
// cwd) resolved as "is CWD inside CWD?" (true). That is a footgun for
// callers that omit an explicit empty check and would let unset config
// values silently widen the sandbox to the working directory. The helper
// must always return false on empty inputs, regardless of CWD.
func TestIsPathWithinDirectoryRejectsEmptyInputs(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Empty directory must be rejected even when path equals or is below CWD.
	if IsPathWithinDirectory(cwd, "") {
		t.Fatal("empty directory must never be treated as CWD")
	}
	if IsPathWithinDirectory(filepath.Join(cwd, "anywhere"), "") {
		t.Fatal("empty directory must reject CWD-relative paths")
	}

	// Empty path must be rejected even when directory is CWD.
	if IsPathWithinDirectory("", cwd) {
		t.Fatal("empty path must never be treated as CWD")
	}
	if IsPathWithinDirectory("", "/some/dir") {
		t.Fatal("empty path must reject any directory")
	}

	// Both empty: trivially false.
	if IsPathWithinDirectory("", "") {
		t.Fatal("empty path and directory must be rejected")
	}
}

// TestIsPathWithinDirectoryRejectsRelativeInputsViaCWD covers the related
// footgun where a "." path or a bare-relative path resolves to CWD via
// filepath.Abs. The helper still canonicalizes them, so the assertion is
// "Rel from a real anchor directory rejects them" — matching the intent
// that callers always pass an explicit, non-empty anchor.
func TestIsPathWithinDirectoryRejectsRelativeInputsViaCWD(t *testing.T) {
	otherDir := t.TempDir()

	// A bare "." or "./foo" canonicalizes to CWD or CWD/foo. Unless CWD is
	// otherDir (it isn't — t.TempDir produces a fresh path), Rel resolves
	// to a parent traversal and the helper rejects.
	if IsPathWithinDirectory(".", otherDir) {
		t.Fatal("CWD-relative \".\" must not satisfy a different anchor dir")
	}
	if IsPathWithinDirectory("./inner", otherDir) {
		t.Fatal("CWD-relative \"./inner\" must not satisfy a different anchor dir")
	}
}

// FuzzIsPathWithinDirectory is a property test asserting the contract:
// when IsPathWithinDirectory returns true, lexically computing
// filepath.Rel between the cleaned-and-canonicalized arguments must not
// produce a parent traversal. We canonicalize via the same helper used
// internally; if a fuzz seed ever finds a discrepancy that's a real
// containment bypass.
func FuzzIsPathWithinDirectory(f *testing.F) {
	f.Add("foo", "/tmp")
	f.Add("../foo", "/tmp")
	f.Add("/etc/passwd", "/tmp")
	f.Add("foo/../bar", "/tmp")
	f.Add("..", "/tmp")
	f.Add("\x00..", "/tmp")
	f.Add("a/b/../../c", "/tmp/d")
	f.Add(strings.Repeat("../", 50), "/tmp")

	f.Fuzz(func(t *testing.T, path, directory string) {
		if !IsPathWithinDirectory(path, directory) {
			return
		}
		// Recompute the canonical relation independently and assert no
		// escape. We use the same canonicalizePath path to defeat
		// platform-dependent symlink resolution.
		canonPath := canonicalizePath(path)
		canonDir := canonicalizePath(directory)
		rel, err := filepath.Rel(canonDir, canonPath)
		if err != nil {
			t.Fatalf("Rel error: path=%q dir=%q canonPath=%q canonDir=%q",
				path, directory, canonPath, canonDir)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("IsPathWithinDirectory accepted escape: path=%q dir=%q rel=%q",
				path, directory, rel)
		}
	})
}

// TestIsPathWithinDirectoryRejectsSiblingPrefix locks in the invariant
// this whole helper exists to enforce: a sibling directory whose path
// happens to share a textual prefix with the trusted directory (e.g.
// "/trusted-dir" vs "/trusted-dir-evil") must never satisfy containment.
// The original lexical strings.HasPrefix checks scattered across the
// codebase failed exactly this case; documenting it at the source — not
// just at every call site — is what callers should rely on.
func TestIsPathWithinDirectoryRejectsSiblingPrefix(t *testing.T) {
	baseDir := t.TempDir()
	siblingDir := baseDir + "-evil"
	if err := os.MkdirAll(siblingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	siblingFile := filepath.Join(siblingDir, "payload.txt")
	if err := os.WriteFile(siblingFile, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}

	if IsPathWithinDirectory(siblingFile, baseDir) {
		t.Fatalf("sibling-prefix path %q must NOT be reported inside %q",
			siblingFile, baseDir)
	}
	if IsPathWithinDirectory(siblingDir, baseDir) {
		t.Fatalf("sibling-prefix dir %q must NOT be reported inside %q",
			siblingDir, baseDir)
	}

	// Non-existent sibling-prefix path: same answer. Canonicalization must
	// still reject because the existing prefix it walks up to is the
	// sibling directory itself, not a child of baseDir.
	missingInSibling := filepath.Join(siblingDir, "does", "not", "exist.txt")
	if IsPathWithinDirectory(missingInSibling, baseDir) {
		t.Fatalf("non-existent sibling-prefix %q must NOT be reported inside %q",
			missingInSibling, baseDir)
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

	missingChildFile := filepath.Join(aliasDir, "helpers", "missing.js")
	if !IsPathWithinDirectory(missingChildFile, realDir) {
		t.Fatalf("expected non-existent child %q to be inside real dir %q", missingChildFile, realDir)
	}
}
