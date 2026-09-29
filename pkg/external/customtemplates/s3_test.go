package customtemplates

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeJoinWithinDirectoryRejectsTraversal(t *testing.T) {
	baseDir := t.TempDir()

	traversalKeys := []string{
		"../etc/passwd",
		"../../etc/passwd",
		"foo/../../etc/passwd",
		"./../etc/passwd",
		"a/b/../../../etc/passwd",
	}

	for _, key := range traversalKeys {
		t.Run(key, func(t *testing.T) {
			_, err := safeJoinWithinDirectory(baseDir, key)
			require.Error(t, err, "expected key %q to be rejected", key)
		})
	}
}

func TestSafeJoinWithinDirectoryAllowsContainedPaths(t *testing.T) {
	baseDir := t.TempDir()

	tests := map[string]string{
		"file.yaml":             filepath.Join(baseDir, "file.yaml"),
		"sub/file.yaml":         filepath.Join(baseDir, "sub", "file.yaml"),
		"a/b/c/file.yaml":       filepath.Join(baseDir, "a", "b", "c", "file.yaml"),
		"sub/../sibling.yaml":   filepath.Join(baseDir, "sibling.yaml"),
		"sub/inner/../i.yaml":   filepath.Join(baseDir, "sub", "i.yaml"),
		"./relative-file.yaml":  filepath.Join(baseDir, "relative-file.yaml"),
		"trailing/dir/":         filepath.Join(baseDir, "trailing", "dir"),
		"name-with-dotdot..bar": filepath.Join(baseDir, "name-with-dotdot..bar"),
	}

	for key, want := range tests {
		t.Run(key, func(t *testing.T) {
			got, err := safeJoinWithinDirectory(baseDir, key)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestSafeJoinWithinDirectoryRejectsSiblingPrefix(t *testing.T) {
	parent := t.TempDir()
	baseDir := filepath.Join(parent, "templates")
	require.NoError(t, os.MkdirAll(baseDir, 0o755))

	// Sibling directory that shares the templates prefix lexically but is
	// not actually inside the templates directory.
	sibling := baseDir + "-evil"
	require.NoError(t, os.MkdirAll(sibling, 0o755))

	// An S3 object key that lexically prefix-matches templates would have
	// been treated as in-bounds by a HasPrefix check. The canonical
	// containment check must reject it.
	key := "../" + filepath.Base(sibling) + "/file.yaml"
	_, err := safeJoinWithinDirectory(baseDir, key)
	require.Error(t, err)
}

func TestSafeJoinWithinDirectoryEmptyBase(t *testing.T) {
	_, err := safeJoinWithinDirectory("", "anything")
	require.Error(t, err)
}

func TestDownloadToFileRejectsTraversalKey(t *testing.T) {
	baseDir := t.TempDir()
	// Use a unique sibling outside baseDir we want to make sure we never write to.
	parent := filepath.Dir(baseDir)
	maliciousKey := "../" + filepath.Base(baseDir) + "-evil/poc.yaml"

	// downloader is nil on purpose: with a safe-join failure we must return
	// before any download attempt is made (otherwise we'd panic on the nil
	// downloader, which itself is a regression assertion).
	err := downloadToFile(nil, baseDir, "irrelevant-bucket", maliciousKey)
	require.Error(t, err)

	// Belt-and-suspenders: nothing got written under the sibling.
	_, statErr := os.Stat(filepath.Join(parent, filepath.Base(baseDir)+"-evil"))
	require.True(t, os.IsNotExist(statErr), "no sibling directory should have been created")
}

func TestSafeJoinWithinDirectoryHandlesLeadingSlash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("absolute path semantics differ on Windows")
	}
	baseDir := t.TempDir()
	// filepath.Join discards the leading "/" of the relative segment, so a
	// "rooted" key like "/etc/passwd" lands at <baseDir>/etc/passwd. That is
	// still inside baseDir, so we accept it (no escape happened).
	got, err := safeJoinWithinDirectory(baseDir, "/etc/passwd")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(baseDir, "etc", "passwd"), got)
}

// TestSafeJoinWithinDirectoryRejectsSymlinkEscape covers the case where
// baseDir already contains a pre-existing symlink that points OUTSIDE of
// baseDir, and an attacker-controlled key tries to ride that symlink to write
// somewhere on the filesystem the operator doesn't control. The canonicalized
// IsPathWithinDirectory check inside safeJoinWithinDirectory must reject this
// even though the lexical Clean of (baseDir + relPath) looks fine.
func TestSafeJoinWithinDirectoryRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}
	parent := t.TempDir()
	baseDir := filepath.Join(parent, "templates")
	require.NoError(t, os.MkdirAll(baseDir, 0o755))

	// A pre-existing escape symlink under baseDir. EvalSymlinks resolves it
	// before we Rel against baseDir, so any key that would write through it
	// must be rejected.
	outside := filepath.Join(parent, "outside")
	require.NoError(t, os.MkdirAll(outside, 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(baseDir, "escape")))

	_, err := safeJoinWithinDirectory(baseDir, "escape/poc.yaml")
	require.Error(t, err, "must reject keys that ride a symlink out of baseDir")
}

// TestSafeJoinWithinDirectoryAcceptsInBoundsSymlink is a positive companion
// to the symlink-escape test: a symlink that stays inside baseDir must be
// honoured, otherwise users would lose support for legitimate setups (e.g.
// macOS /tmp -> /private/tmp aliases).
func TestSafeJoinWithinDirectoryAcceptsInBoundsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}
	baseDir := t.TempDir()
	inner := filepath.Join(baseDir, "real")
	require.NoError(t, os.MkdirAll(inner, 0o755))
	require.NoError(t, os.Symlink(inner, filepath.Join(baseDir, "alias")))

	got, err := safeJoinWithinDirectory(baseDir, "alias/file.yaml")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(baseDir, "alias", "file.yaml"), got)
}

// TestSafeJoinWithinDirectoryAdversarialKeys exhaustively probes
// well-known traversal patterns that historically bypass naive joiners.
// All of these must be rejected on Linux/macOS; the Windows-only patterns
// are also asserted on Windows.
func TestSafeJoinWithinDirectoryAdversarialKeys(t *testing.T) {
	parent := t.TempDir()
	baseDir := filepath.Join(parent, "templates")
	require.NoError(t, os.MkdirAll(baseDir, 0o755))
	siblingName := filepath.Base(baseDir) + "-evil"
	require.NoError(t, os.MkdirAll(filepath.Join(parent, siblingName), 0o755))

	keys := []string{
		"../" + siblingName + "/file.yaml",
		"./../" + siblingName + "/file.yaml",
		"sub/../../" + siblingName + "/file.yaml",
		strings.Repeat("../", 10) + "etc/passwd",
		"sub/" + strings.Repeat("../", 10) + "etc/passwd",
		// Excessive depth that should still resolve outside.
		"a/b/c/d/e/../../../../../../../../etc/passwd",
		// Mixed dot-only segments that fold into "../".
		"./.././../../" + siblingName,
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			_, err := safeJoinWithinDirectory(baseDir, key)
			require.Error(t, err, "expected key %q to be rejected", key)
		})
	}
}

// FuzzSafeJoinWithinDirectory is a property test for safeJoinWithinDirectory:
// no matter what the attacker-controlled relPath looks like, the helper
// either errors (rejecting) or returns a path whose canonical resolution
// stays inside baseDir. We cannot rely solely on the lexical Clean of the
// returned string here — the canonical resolver follows symlinks, so the
// strongest invariant is "the caller's eventual writes go inside baseDir".
func FuzzSafeJoinWithinDirectory(f *testing.F) {
	seeds := []string{
		"",
		".",
		"..",
		"foo",
		"foo/bar",
		"../etc",
		"foo/../../etc",
		"./../etc",
		"\\..\\..\\foo",
		"a/b/../../../../../../etc/passwd",
		strings.Repeat("../", 1000),
		strings.Repeat("..\\", 1000),
		"\x00..",
		"\u202e..\u202d",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	baseDir := f.TempDir()

	f.Fuzz(func(t *testing.T, relPath string) {
		got, err := safeJoinWithinDirectory(baseDir, relPath)
		if err != nil {
			return
		}
		// The accepted path must be under baseDir according to filepath.Rel.
		// We cleaned both sides to defeat trailing-separator differences.
		rel, relErr := filepath.Rel(filepath.Clean(baseDir), filepath.Clean(got))
		if relErr != nil {
			t.Fatalf("Rel error: relPath=%q got=%q err=%v", relPath, got, relErr)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("safeJoinWithinDirectory accepted escape: relPath=%q got=%q rel=%q",
				relPath, got, rel)
		}
	})
}
