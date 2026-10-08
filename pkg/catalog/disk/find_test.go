package disk

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// TestFindGlobPathMatchesUsesCanonicalContainment ensures that when an
// absPath shares a lexical prefix with templatesDirectory but is not actually
// inside it (a sibling-prefix path), the embedded-FS lookup does NOT silently
// strip part of the prefix and resolve into the templates root.
func TestFindGlobPathMatchesUsesCanonicalContainment(t *testing.T) {
	// Build a small in-memory FS that simulates an embedded templates tree
	// and a sibling tree. fs.Glob is rooted at the FS root, so the test
	// asserts that with the buggy prefix-trim a sibling-prefix glob would
	// match the in-bounds entry; with the fix it does not.
	memFS := fstest.MapFS{
		"http/test.yaml":      {Data: []byte("legit")},
		"http-evil/test.yaml": {Data: []byte("sibling")},
	}

	templatesDir := filepath.Join(t.TempDir(), "templates")

	cat := NewFSCatalog(memFS, templatesDir)

	// Glob for siblings of templatesDir (the previous TrimPrefix would have
	// silently aliased "/.../templates-evil/*.yaml" into "-evil/*.yaml" and
	// then collapsed to a glob with no leading separator that ran against
	// memFS root — observable as confused matches in production code paths
	// that rely on this method).
	sibling := templatesDir + "-evil"
	matches, err := cat.findGlobPathMatches(filepath.Join(sibling, "*.yaml"), map[string]struct{}{})
	require.NoError(t, err)
	// Whatever the glob produces, it must NOT include the in-bounds
	// http/test.yaml from inside the templates directory.
	for _, m := range matches {
		require.NotContains(t, m, "http/test.yaml",
			"sibling-prefix glob must not alias into the templates root")
	}
}

func TestFindGlobPathMatchesResolvesContainedPath(t *testing.T) {
	memFS := fstest.MapFS{
		"http/test.yaml": {Data: []byte("legit")},
	}

	templatesDir := filepath.Join(t.TempDir(), "templates")
	cat := NewFSCatalog(memFS, templatesDir)

	// A glob that lives inside templatesDir resolves correctly via the
	// canonical relative path (no surprises from the rewrite).
	matches, err := cat.findGlobPathMatches(filepath.Join(templatesDir, "http", "*.yaml"), map[string]struct{}{})
	require.NoError(t, err)
	require.Equal(t, []string{"http/test.yaml"}, matches)
}

// TestGetTemplatesPathKnownConfigFiles ensures that only exact known config
// file names are skipped, and templates whose names merely contain one (e.g.
// cves.json.yaml) are still loaded.
func TestGetTemplatesPathKnownConfigFiles(t *testing.T) {
	templatesDir := t.TempDir()
	httpDir := filepath.Join(templatesDir, "http")
	require.NoError(t, os.MkdirAll(httpDir, 0755))

	template := filepath.Join(httpDir, "cves.json.yaml")
	for _, f := range []string{
		template,
		filepath.Join(templatesDir, "cves.json"),
		filepath.Join(templatesDir, "contributors.json"),
		filepath.Join(templatesDir, "TEMPLATES-STATS.json"),
	} {
		require.NoError(t, os.WriteFile(f, []byte("id: test"), 0644))
	}

	cat := NewCatalog(templatesDir)

	t.Run("direct path", func(t *testing.T) {
		paths, errs := cat.GetTemplatesPath([]string{template})
		require.Empty(t, errs)
		require.Equal(t, []string{template}, paths)
	})

	t.Run("directory traversal", func(t *testing.T) {
		paths, errs := cat.GetTemplatesPath([]string{templatesDir})
		require.Empty(t, errs)
		require.Equal(t, []string{template}, paths)
	})

	t.Run("config file is skipped", func(t *testing.T) {
		paths, errs := cat.GetTemplatesPath([]string{filepath.Join(templatesDir, "cves.json")})
		require.Empty(t, errs)
		require.Empty(t, paths)
	})
}
