package output

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHostCandidate(t *testing.T) {
	t.Run("URL", func(t *testing.T) {
		require.Equal(t, "example.com", normalizeHostCandidate("https://example.com/test?q=1"))
	})

	t.Run("HostPort", func(t *testing.T) {
		require.Equal(t, "example.com", normalizeHostCandidate("example.com:8443"))
	})

	t.Run("HostOnly", func(t *testing.T) {
		require.Equal(t, "example.com", normalizeHostCandidate("EXAMPLE.COM"))
	})
}

func TestStandardWriterHoneypotThresholdWarnOnly(t *testing.T) {
	writer, err := NewStandardWriter(&types.Options{JSONL: true, HoneypotThreshold: 2})
	require.NoError(t, err)
	writer.DisableStdout = true
	output := &testWriteCloser{}
	writer.outputFile = output

	require.NoError(t, writer.Write(&ResultEvent{TemplateID: "tpl-1", Host: "https://example.com", Type: "http"}))
	require.NoError(t, writer.Write(&ResultEvent{TemplateID: "tpl-2", Host: "https://example.com", Type: "http"}))

	require.Equal(t, 2, writer.ResultCount())
	require.Contains(t, output.String(), `"template-id":"tpl-1"`)
	require.Contains(t, output.String(), `"template-id":"tpl-2"`)
}

func TestStandardWriterHoneypotThresholdSuppress(t *testing.T) {
	writer, err := NewStandardWriter(&types.Options{JSONL: true, HoneypotThreshold: 2, HoneypotSuppressResults: true})
	require.NoError(t, err)
	writer.DisableStdout = true
	output := &testWriteCloser{}
	writer.outputFile = output

	require.NoError(t, writer.Write(&ResultEvent{TemplateID: "tpl-1", URL: "https://example.com", Type: "http"}))
	require.NoError(t, writer.Write(&ResultEvent{TemplateID: "tpl-2", URL: "https://example.com", Type: "http"}))

	require.Equal(t, 1, writer.ResultCount())
	require.Contains(t, output.String(), `"template-id":"tpl-1"`)
	require.NotContains(t, output.String(), `"template-id":"tpl-2"`)
}
