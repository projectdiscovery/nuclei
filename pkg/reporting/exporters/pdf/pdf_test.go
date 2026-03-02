package pdf

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phpdave11/gofpdf"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultsAndCreatesOutputDirectory(t *testing.T) {
	chdirTemp(t)
	outputFile := filepath.Join("reports", "scan-report.pdf")

	exporter, err := New(&Options{File: outputFile})
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.Equal(t, outputFile, exporter.options.File)

	info, err := os.Stat(filepath.Dir(outputFile))
	require.NoError(t, err)
	require.True(t, info.IsDir())

	defaultExporter, err := New(nil)
	require.NoError(t, err)
	require.Equal(t, defaultFileName, defaultExporter.options.File)
}

func TestExportIgnoresNilEvent(t *testing.T) {
	chdirTemp(t)
	exporter, err := New(&Options{File: "report.pdf"})
	require.NoError(t, err)

	require.NoError(t, exporter.Export(nil))
	require.Empty(t, exporter.results)
}

func TestCloseWithoutResultsDoesNotCreateFile(t *testing.T) {
	chdirTemp(t)
	outputFile := "empty.pdf"

	exporter, err := New(&Options{File: outputFile})
	require.NoError(t, err)
	require.NoError(t, exporter.Close())

	_, statErr := os.Stat(outputFile)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCloseWritesPDFAndRespectsOmitRaw(t *testing.T) {
	reset := setDefaultCompression(t, false)
	defer reset()

	chdirTemp(t)
	outputFile := "findings.pdf"

	exporter, err := New(&Options{File: outputFile, OmitRaw: true})
	require.NoError(t, err)

	event := buildEvent("example.com", severity.High)
	event.Request = "GET /secret HTTP/1.1"
	event.Response = "secret-response-body"

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	pdfData, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	require.NotEmpty(t, pdfData)

	content := string(pdfData)
	require.Contains(t, content, "Nuclei Scan Report")
	require.Contains(t, content, "Severity Summary")
	require.NotContains(t, content, "secret-response-body")
	require.NotContains(t, content, "GET /secret HTTP/1.1")
}

func TestCloseTruncatesLargeRawBlocks(t *testing.T) {
	reset := setDefaultCompression(t, false)
	defer reset()

	chdirTemp(t)
	outputFile := "large-raw.pdf"

	exporter, err := New(&Options{File: outputFile, OmitRaw: false})
	require.NoError(t, err)

	event := buildEvent("raw.example.com", severity.Medium)
	event.Response = "START-" + strings.Repeat("A", maxRawBlockRunes+500) + "-END-MARKER"

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	pdfData, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	content := string(pdfData)
	require.Contains(t, content, "START-")
	require.Contains(t, content, strings.TrimSpace(rawBlockTruncatedSuffix))
	require.NotContains(t, content, "END-MARKER")
}

func TestConcurrentExportAndClose(t *testing.T) {
	chdirTemp(t)
	outputFile := "concurrent.pdf"

	exporter, err := New(&Options{File: outputFile})
	require.NoError(t, err)

	var wg sync.WaitGroup
	errCh := make(chan error, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			event := buildEvent("concurrent.example.com", severity.Low)
			event.TemplateID = "tmpl-concurrent-" + time.Unix(int64(index), 0).UTC().Format("150405")
			errCh <- exporter.Export(event)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for exportErr := range errCh {
		require.NoError(t, exportErr)
	}

	require.Len(t, exporter.results, 30)
	require.NoError(t, exporter.Close())

	info, err := os.Stat(outputFile)
	require.NoError(t, err)
	require.True(t, info.Size() > 0)
}

func TestNewRejectsParentTraversalPath(t *testing.T) {
	_, err := New(&Options{File: "../outside/report.pdf"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "parent directory traversal")
}

func TestNewRejectsAbsolutePath(t *testing.T) {
	absolutePath := filepath.Join(string(os.PathSeparator), "tmp", "outside", "report.pdf")

	_, err := New(&Options{File: absolutePath})

	require.Error(t, err)
	require.Contains(t, err.Error(), "absolute path")
}

func setDefaultCompression(t *testing.T, enabled bool) func() {
	t.Helper()

	gofpdf.SetDefaultCompression(enabled)

	return func() {
		gofpdf.SetDefaultCompression(true)
	}
}

func chdirTemp(t *testing.T) {
	t.Helper()

	oldWD, err := os.Getwd()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(oldWD))
	})
}

func buildEvent(host string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: "test-template",
		Template:   "http/test-template.yaml",
		Type:       "http",
		Host:       host,
		Matched:    "https://" + host + "/login",
		Path:       "/login",
		Request:    "GET /login HTTP/1.1",
		Response:   "HTTP/1.1 200 OK",
		Timestamp:  time.Date(2026, time.February, 27, 23, 0, 0, 0, time.UTC),
		Info: model.Info{
			Name:           "Test finding",
			Description:    "A reproducible test finding",
			SeverityHolder: severity.Holder{Severity: sev},
			Reference:      stringslice.NewRawStringSlice("https://docs.example.com/finding"),
		},
	}
}
