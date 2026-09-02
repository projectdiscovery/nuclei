package disk

import (
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

func TestGetTemplatesPathAllowsNamesContainingKnownConfigFiles(t *testing.T) {
	const templatePath = "http/cves.json.yaml"
	catalog := NewFSCatalog(fstest.MapFS{
		templatePath: {Data: []byte("id: test")},
	}, t.TempDir())

	for _, definitions := range [][]string{{templatePath}, {"http"}} {
		templates, errs := catalog.GetTemplatesPath(definitions)
		require.Empty(t, errs)
		require.Equal(t, []string{templatePath}, templates)
	}
}

func TestGetTemplatesPathSkipsKnownConfigFiles(t *testing.T) {
	catalog := NewFSCatalog(fstest.MapFS{
		"http/cves.json.yaml":  {Data: []byte("id: tmpl")},
		"http/ok.yaml":         {Data: []byte("id: ok")},
		"cves.json":            {Data: []byte("[]")},
		"contributors.json":    {Data: []byte("[]")},
		"TEMPLATES-STATS.json": {Data: []byte("{}")},
	}, t.TempDir())

	templates, errs := catalog.GetTemplatesPath([]string{"cves.json"})
	require.Empty(t, errs)
	require.Empty(t, templates)

	templates, errs = catalog.GetTemplatesPath([]string{"."})
	require.Empty(t, errs)
	require.ElementsMatch(t, []string{"http/cves.json.yaml", "http/ok.yaml"}, templates)
}

func TestGetTemplatesPathRemoteDefinitionsUsePathExtension(t *testing.T) {
	catalog := NewFSCatalog(fstest.MapFS{}, t.TempDir())

	yamlURL := "https://example.com/templates/cves.json.yaml"
	templates, errs := catalog.GetTemplatesPath([]string{yamlURL})
	require.Empty(t, errs)
	require.Equal(t, []string{yamlURL}, templates)

	queryURL := "https://example.com/templates/ok.yaml?ref=cves.json"
	templates, errs = catalog.GetTemplatesPath([]string{queryURL})
	require.Empty(t, errs)
	require.Equal(t, []string{queryURL}, templates)

	configURL := "https://example.com/nuclei-templates/cves.json"
	templates, errs = catalog.GetTemplatesPath([]string{configURL})
	require.Empty(t, errs)
	require.Empty(t, templates)

	jsonlURL := "https://example.com/data.jsonl"
	templates, errs = catalog.GetTemplatesPath([]string{jsonlURL})
	require.NotContains(t, templates, jsonlURL)
	require.Contains(t, errs, jsonlURL)
}
