package pdf

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func makeEvent(sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "http://example.com",
		Matched:    "http://example.com/vulnerable",
		Type:       "http",
		Timestamp:  time.Now(),
		Info: model.Info{
			Name:           "Test Finding",
			Authors:        stringslice.StringSlice{Value: "test"},
			SeverityHolder: severity.Holder{Severity: sev},
			Description:    "A test vulnerability description.",
		},
		Request:  "GET / HTTP/1.1\r\nHost: example.com",
		Response: "HTTP/1.1 200 OK\r\nContent-Type: text/html",
	}
}

func TestNew_Defaults(t *testing.T) {
	exp, err := New(&Options{})
	require.NoError(t, err)
	require.Equal(t, defaultFile, exp.options.File)
}

func TestNew_CustomFile(t *testing.T) {
	exp, err := New(&Options{File: "custom.pdf"})
	require.NoError(t, err)
	require.Equal(t, "custom.pdf", exp.options.File)
}

func TestExport_NilEvent(t *testing.T) {
	exp, err := New(&Options{File: "test.pdf"})
	require.NoError(t, err)
	require.NoError(t, exp.Export(nil))
	require.Empty(t, exp.results)
}

func TestClose_EmptyResults(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.pdf")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)
	require.NoError(t, exp.Close())
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr))
}

func TestClose_WritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.pdf")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)
	require.NoError(t, exp.Export(makeEvent(severity.High)))
	require.NoError(t, exp.Close())

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0))
}

func TestExport_OmitRaw(t *testing.T) {
	exp, err := New(&Options{File: "test.pdf", OmitRaw: true})
	require.NoError(t, err)
	event := makeEvent(severity.High)
	require.NoError(t, exp.Export(event))

	require.Len(t, exp.results, 1)
	require.Empty(t, exp.results[0].Request)
	require.Empty(t, exp.results[0].Response)
	require.NotEmpty(t, event.Request)
	require.NotEmpty(t, event.Response)
}

func TestExport_Concurrency(t *testing.T) {
	exp, err := New(&Options{File: filepath.Join(t.TempDir(), "report.pdf")})
	require.NoError(t, err)

	const workers = 50
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			errs <- exp.Export(makeEvent(severity.Medium))
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	require.Len(t, exp.results, workers)
}

func TestSafeStr_ReplacesNonLatin1(t *testing.T) {
	result := safeStr("hello 世界")
	require.Equal(t, "hello ??", result)
}
