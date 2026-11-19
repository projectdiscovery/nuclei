package jsonl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestCloseReleasesFileAfterFlushFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		readOnly  bool
		event     output.ResultEvent
		wantError string
	}{
		{name: "write error", readOnly: true, wantError: "failed to append JSONL line"},
		{name: "marshal error", event: output.ResultEvent{Metadata: map[string]interface{}{"unsupported": make(chan int)}}, wantError: "failed to generate row for JSONL report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results.jsonl")
			flags := os.O_RDWR | os.O_CREATE
			if tc.readOnly {
				require.NoError(t, os.WriteFile(path, nil, 0600))
				flags = os.O_RDONLY
			}
			file, err := os.OpenFile(path, flags, 0600)
			require.NoError(t, err)
			t.Cleanup(func() { _ = file.Close() })
			exporter, err := New(&Options{File: path})
			require.NoError(t, err)
			exporter.outputFile = file
			require.NoError(t, exporter.Export(&tc.event))
			err = exporter.Close()
			require.ErrorContains(t, err, tc.wantError)
			_, err = file.Read(make([]byte, 1))
			require.ErrorIs(t, err, os.ErrClosed, "Close must release the file even when flushing fails")
		})
	}
}

func TestCloseReportsCreateFailure(t *testing.T) {
	exporter, err := New(&Options{File: filepath.Join(t.TempDir(), "missing", "results.jsonl")})
	require.NoError(t, err)
	require.ErrorContains(t, exporter.Close(), "failed to create JSONL file")
}

func TestCloseFlushesPendingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.jsonl")
	exporter, err := New(&Options{File: path, BatchSize: 2})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "first"}))
	require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "second"}))
	file := exporter.outputFile
	require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "pending"}))
	require.NoError(t, exporter.Close())
	_, err = file.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrClosed)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"template-id":"first"`)
	require.Contains(t, string(data), `"template-id":"second"`)
	require.Contains(t, string(data), `"template-id":"pending"`)
}
