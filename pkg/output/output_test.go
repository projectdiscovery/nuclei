package output

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
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

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}

func TestResultEventRequestIdentityJSONCompatibility(t *testing.T) {
	legacy := []byte(`{"template-id":"legacy","info":{"name":"legacy","author":["test"],"severity":"info"},"type":"http","matched-at":"https://example.com","matcher-status":true,"timestamp":"2026-01-01T00:00:00Z"}`)
	var decoded ResultEvent
	require.NoError(t, json.Unmarshal(legacy, &decoded))
	require.Equal(t, "legacy", decoded.TemplateID)
	require.Empty(t, decoded.RequestID)
	require.Empty(t, decoded.RequestBlockID)
	require.Zero(t, decoded.RequestProbeIndex)
	require.Empty(t, decoded.RequestProbeID)

	encoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "request-id")
	require.NotContains(t, string(encoded), "request-block-id")
	require.NotContains(t, string(encoded), "request-probe-index")
	require.NotContains(t, string(encoded), "request-probe-id")

	decoded.RequestID = "ssl_2"
	decoded.RequestBlockID = "v1:ssl:explicit:certificate"
	decoded.RequestProbeIndex = 3
	decoded.RequestProbeID = "v1:ssl:probe-sha256:abc"
	encoded, err = json.Marshal(&decoded)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"request-id":"ssl_2"`)
	require.Contains(t, string(encoded), `"request-block-id":"v1:ssl:explicit:certificate"`)
	require.Contains(t, string(encoded), `"request-probe-index":3`)
	require.Contains(t, string(encoded), `"request-probe-id":"v1:ssl:probe-sha256:abc"`)

	var roundTrip ResultEvent
	require.NoError(t, json.Unmarshal(encoded, &roundTrip))
	require.Equal(t, "ssl_2", roundTrip.RequestID)
	require.Equal(t, "v1:ssl:explicit:certificate", roundTrip.RequestBlockID)
	require.Equal(t, 3, roundTrip.RequestProbeIndex)
	require.Equal(t, "v1:ssl:probe-sha256:abc", roundTrip.RequestProbeID)
}

func TestCloneShallowKeepsRequestProbeIndex(t *testing.T) {
	event := &InternalWrappedEvent{InternalEvent: InternalEvent{"k": "v"}, RequestProbeIndex: 2, RequestProbeID: "probe-b"}

	require.Equal(t, 2, event.CloneShallow().RequestProbeIndex)
	require.Equal(t, "probe-b", event.CloneShallow().RequestProbeID)
}
