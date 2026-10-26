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

func TestFormatScreenIncludesConfidenceScore(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{NoColor: true})
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	formatted := string(w.formatScreen(&ResultEvent{
		TemplateID:      "test-template",
		Type:            "http",
		Host:            "example.com",
		Confidence:      "low",
		ConfidenceScore: 0,
	}))
	require.Contains(t, formatted, "[low (0)]")
}

func TestResultEventSerializesZeroConfidenceScore(t *testing.T) {
	data, err := json.Marshal(&ResultEvent{Confidence: "low", ConfidenceScore: 0})
	require.NoError(t, err)
	require.Contains(t, string(data), `"confidence-score":0`)
}

func TestWriteFailureReportsNoConfidence(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{JSONL: true, MatcherStatus: true})
	require.NoError(t, err)
	out := &testWriteCloser{}
	w.outputFile = out
	w.DisableStdout = true

	err = w.WriteFailure(&InternalWrappedEvent{InternalEvent: InternalEvent{
		"template-id": "failed-template",
		"host":        "https://example.com",
		"type":        "http",
	}})
	require.NoError(t, err)

	var event map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out.String())), &event))
	require.Equal(t, false, event["matcher-status"])
	require.Equal(t, ConfidenceNone, event["confidence"])
	require.Equal(t, float64(0), event["confidence-score"])
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
