package markdown

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestExportDoesNotIndexFailedReport(t *testing.T) {
	dir := t.TempDir()
	exporter, err := New(&Options{Directory: dir, SortMode: "host"})
	require.NoError(t, err)
	indexPath := filepath.Join(dir, indexFileName)

	// Keep a successfully exported finding in the index, then make the next
	// report's parent a regular file. This fails on Windows and Unix without
	// relying on the effective user's permission bits.
	require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "first", Host: "working.example"}))
	before, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	require.Contains(t, string(before), "first")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked.example"), []byte("not a directory"), 0600))

	err = exporter.Export(&output.ResultEvent{TemplateID: "failed", Host: "blocked.example"})
	require.Error(t, err)
	after, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "a report that could not be written must not be linked in the index")
}

func TestExportIndexesWrittenReport(t *testing.T) {
	for _, mode := range []string{"", "host", "template", "severity"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			exporter, err := New(&Options{Directory: dir, SortMode: mode})
			require.NoError(t, err)
			require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "test-template", Host: "example.com"}))
			index, err := os.ReadFile(filepath.Join(dir, indexFileName))
			require.NoError(t, err)
			text := string(index)
			start := strings.Index(text, "[example.com](")
			require.NotEqual(t, -1, start)
			target := strings.SplitN(text[start+len("[example.com]("):], ")", 2)[0]
			report, err := os.ReadFile(filepath.Join(dir, target))
			require.NoError(t, err, "index target must name an existing report")
			require.Contains(t, string(report), "test-template")
		})
	}
}

func TestExportRejectsMissingIndexBeforeWritingReport(t *testing.T) {
	dir := t.TempDir()
	exporter, err := New(&Options{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, indexFileName)))
	require.Error(t, exporter.Export(&output.ResultEvent{TemplateID: "test-template", Host: "example.com"}))
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, files)
}
