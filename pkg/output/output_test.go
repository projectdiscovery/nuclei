package output

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
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

// Only the fields filled from a response are redacted; text the template wrote
// stays as it is, even next to a filled field.
func TestStandardWriterRedactsFilledInfo(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{Redact: goflags.StringSlice{"password"}})
	require.NoError(t, err)
	w.DisableStdout = true

	written := model.Info{Description: "login with password: {{password}}", Remediation: "Rotate the password: it is public"}
	filled := &ResultEvent{TemplateInfo: &written, Info: model.Info{Description: "login with password: admin", Remediation: written.Remediation}}
	static := &ResultEvent{Info: model.Info{Description: "send the password: header"}}
	require.NoError(t, w.Write(filled))
	require.NoError(t, w.Write(static))

	require.Equal(t, "login with password: ***", filled.Info.Description)
	require.Equal(t, "Rotate the password: it is public", filled.Info.Remediation)
	require.Equal(t, "send the password: header", static.Info.Description)
}

// The mongo exporter serializes results with bson, which ignores json tags.
func TestResultEventKeepsTemplateInfoOutOfBSON(t *testing.T) {
	written := model.Info{Description: "{{host}} is exposed"}
	data, err := bson.Marshal(&ResultEvent{TemplateInfo: &written, Info: model.Info{Description: "example.com is exposed"}})
	require.NoError(t, err)

	var doc bson.M
	require.NoError(t, bson.Unmarshal(data, &doc))
	require.NotContains(t, doc, "templateinfo")
	require.Contains(t, doc, "info")
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}
