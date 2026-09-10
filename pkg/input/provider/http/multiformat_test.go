package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestHttpInputProviderDeduplicatesJSONL(t *testing.T) {
	t.Parallel()

	// Three lines: two equivalent GETs (different Cookie / query order) and one unique POST.
	input := "" +
		`{"url":"https://example.com/search?q=1&lang=en","request":{"raw":"GET /search?q=1&lang=en HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\n\r\n"}}` + "\n" +
		`{"url":"https://example.com/search?lang=en&q=1","request":{"raw":"GET /search?lang=en&q=1 HTTP/1.1\r\nHost: example.com\r\nCookie: a=2\r\n\r\n"}}` + "\n" +
		`{"url":"https://example.com/search","request":{"raw":"POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"x\":1}"}}` + "\n"

	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "jsonl",
		InputContents: input,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), provider.Count())
	require.Equal(t, int64(1), provider.dupeCount)

	var methods []string
	provider.Iterate(func(value *contextargs.MetaInput) bool {
		require.NotNil(t, value.ReqResp)
		require.NotNil(t, value.ReqResp.Request)
		methods = append(methods, value.ReqResp.Request.Method+" "+value.Input)
		return true
	})
	require.Len(t, methods, 2)
	require.Contains(t, methods[0], "GET")
	require.Contains(t, methods[1], "POST")
}

func TestHttpInputProviderIterateSkipsDuplicates(t *testing.T) {
	t.Parallel()

	input := "" +
		`{"url":"https://example.com/a","request":{"raw":"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"}}` + "\n" +
		`{"url":"https://example.com/a","request":{"raw":"GET /a HTTP/1.1\r\nHost: example.com\r\nUser-Agent: other\r\n\r\n"}}` + "\n" +
		`{"url":"https://example.com/b","request":{"raw":"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"}}` + "\n"

	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "jsonl",
		InputContents: input,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), provider.Count())
	require.Equal(t, int64(1), provider.dupeCount)

	var urls []string
	provider.Iterate(func(value *contextargs.MetaInput) bool {
		urls = append(urls, value.Input)
		return true
	})
	require.Equal(t, []string{"https://example.com/a", "https://example.com/b"}, urls)
}
