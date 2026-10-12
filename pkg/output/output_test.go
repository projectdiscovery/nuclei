package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestWriteFailureRebuildsEmptyHTTPResponse(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{MatcherStatus: true, JSONL: true})
	require.NoError(t, err)
	buf := &testWriteCloser{}
	w.outputFile = buf
	w.DisableStdout = true

	err = w.WriteFailure(&InternalWrappedEvent{InternalEvent: InternalEvent{
		"template-id":   "example",
		"template-path": "example.yaml",
		"host":          "http://example.com",
		"type":          "http",
		"response":      "",
		"all_headers":   "HTTP/1.1 200 OK\r\n\r\n",
		"body":          "hello",
	}})
	require.NoError(t, err)

	var event map[string]any
	require.NoError(t, json.Unmarshal([]byte(buf.String()), &event))
	require.Equal(t, "HTTP/1.1 200 OK\r\n\r\nhello", event["response"])
	require.Equal(t, false, event["matcher-status"])

	buf.Reset()
	err = w.WriteFailure(&InternalWrappedEvent{InternalEvent: InternalEvent{
		"template-id":   "example",
		"template-path": "example.yaml",
		"host":          "http://example.com",
		"type":          "http",
		"response":      "kept",
		"all_headers":   "HTTP/1.1 200 OK\r\n\r\n",
		"body":          "hello",
	}})
	require.NoError(t, err)
	event = map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(buf.String()), &event))
	require.Equal(t, "kept", event["response"])
}

func TestStandardWriterRequest(t *testing.T) {
	t.Run("WithoutTraceAndError", func(t *testing.T) {
		w, err := NewStandardWriter(&types.Options{})
		require.NoError(t, err)
		require.NotPanics(t, func() {
			w.Request("path", "input", "http", nil)
			w.Close()
		})
	})

	t.Run("TraceAndErrorWithoutError", func(t *testing.T) {
		traceWriter := &testWriteCloser{}
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.traceFile = traceWriter
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request("path", "input", "http", nil)

		require.Equal(t, `{"template":"path","type":"http","input":"input","address":"input:","error":"none"}`, traceWriter.String())
		require.Empty(t, errorWriter.String())
	})

	t.Run("ErrorWithWrappedError", func(t *testing.T) {
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request(
			"misconfiguration/tcpconfig.yaml",
			"https://example.com/tcpconfig.html",
			"http",
			fmt.Errorf("GET https://example.com/tcpconfig.html/tcpconfig.html giving up after 2 attempts: %w", errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")),
		)

		require.Equal(t, `{"template":"misconfiguration/tcpconfig.yaml","type":"http","input":"https://example.com/tcpconfig.html","address":"example.com:443","error":"cause=\"context deadline exceeded (Client.Timeout exceeded while awaiting headers)\"","kind":"unknown-error"}`, errorWriter.String())
	})
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
