package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestRawBodyKeepsTheBytesAsReceived(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.ModTime = time.Unix(1700000000, 0)
	_, _ = writer.Write([]byte(`{"hello":"world"}`))
	require.NoError(t, writer.Close())
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer ts.Close()

	execute := func(t *testing.T, extractor *extractors.Extractor) output.InternalEvent {
		options := testutils.DefaultOptions
		testutils.Init(options)
		request := &Request{
			ID:        "raw-body",
			Path:      []string{"{{BaseURL}}"},
			Operators: operators.Operators{Extractors: []*extractors.Extractor{extractor}},
		}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "raw-body",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
		})
		require.NoError(t, request.Compile(executerOpts))

		var event output.InternalEvent
		err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ts.URL), output.InternalEvent{}, output.InternalEvent{}, func(e *output.InternalWrappedEvent) {
			event = e.InternalEvent
		})
		require.NoError(t, err)
		return event
	}

	t.Run("reading raw_body", func(t *testing.T) {
		event := execute(t, &extractors.Extractor{
			Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
			DSL:  []string{"to_string(gzip_mtime(raw_body))"},
		})
		require.Equal(t, compressed.String(), event["raw_body"])
		require.Contains(t, event["raw_response"], compressed.String())
		require.Equal(t, `{"hello":"world"}`, event["body"], "body stays decoded")
	})
	t.Run("not reading it", func(t *testing.T) {
		event := execute(t, &extractors.Extractor{
			Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
			DSL:  []string{"body"},
		})
		require.NotContains(t, event, "raw_body")
		require.Equal(t, `{"hello":"world"}`, event["body"])
	})
}

func TestReadsRawResponse(t *testing.T) {
	readsRaw := func(request *Request, flow string) bool { return reads(request, flow, "raw_body", "raw_response") }
	require.False(t, readsRaw(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{"admin"}}}}}, ""))
	require.True(t, readsRaw(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Part: "raw_body"}}}}, ""))
	require.True(t, readsRaw(&Request{Operators: operators.Operators{Extractors: []*extractors.Extractor{{DSL: []string{"gzip_mtime(raw_body)"}}}}}, ""))
	require.True(t, readsRaw(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Part: "raw_response"}}}}, ""))
	require.True(t, readsRaw(&Request{}, "http(1) && template.raw_body != ''"))

	require.False(t, (&Request{readsRawResponse: true}).IsClusterable(), "a cluster runs on one member's response")
}
