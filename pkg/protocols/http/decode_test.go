package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestGzipBodyIsDecoded(t *testing.T) {
	const decoded = `{"hello":"world"}`
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(decoded))
	require.NoError(t, writer.Close())

	serve := func(encoding string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", encoding)
			_, _ = w.Write(compressed.Bytes())
		}))
	}
	execute := func(t *testing.T, url, dsl string, request *Request) output.InternalEvent {
		options := testutils.DefaultOptions
		testutils.Init(options)
		request.ID = "decode"
		request.Operators = operators.Operators{Extractors: []*extractors.Extractor{{
			Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
			DSL:  []string{dsl},
		}}}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "decode",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
		})
		require.NoError(t, request.Compile(executerOpts))

		var event output.InternalEvent
		err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), url), output.InternalEvent{}, output.InternalEvent{}, func(e *output.InternalWrappedEvent) {
			event = e.InternalEvent
		})
		require.NoError(t, err)
		return event
	}

	// #8189: reading raw_body sends Accept-Encoding, so nuclei decodes and not the transport
	t.Run("GZip while reading raw_body", func(t *testing.T) {
		ts := serve("GZip")
		defer ts.Close()
		event := execute(t, ts.URL, "raw_body", &Request{Path: []string{"{{BaseURL}}"}})
		require.Equal(t, decoded, event["body"])
	})
	// #8298: rawhttp decodes gzip but keeps Content-Encoding
	t.Run("unsafe", func(t *testing.T) {
		ts := serve("gzip")
		defer ts.Close()
		event := execute(t, ts.URL, "body", &Request{
			Unsafe: true,
			Raw:    []string{"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"},
		})
		require.Equal(t, decoded, event["body"])
	})
}
