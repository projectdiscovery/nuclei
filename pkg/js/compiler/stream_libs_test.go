package compiler

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/stretchr/testify/require"
)

const streamHashScript = `
	const net = require('nuclei/net');
	const compress = require('nuclei/compress');
	const hash = require('nuclei/hash');

	const conn = net.Open('tcp', %q);
	conn.Send('GET / HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n\r\n');
	let head = '';
	while (!head.endsWith('\r\n\r\n')) head += conn.RecvString(1);
	const header = (name) => (head.match(new RegExp('\r\n' + name + ': ([^\r]+)', 'i')) || [])[1];
	const length = header('Content-Length');
	const coding = [header('Content-Encoding'), header('Transfer-Encoding')].filter(Boolean).join(', ');

	const d = compress.NewDecoder(coding);
	const sha = hash.New('sha256'), mmh3 = hash.New('mmh3');
	const take = (out) => { sha.Write(out); mmh3.Write(out); };
	if (length !== undefined) {
		for (let read = 0; read < parseInt(length); ) {
			const chunk = conn.Recv(65536);
			read += chunk.length;
			for (let out = d.Write(chunk); out.length > 0; out = d.Read()) take(out);
		}
		for (let out = d.Close(); out.length > 0; out = d.Read()) take(out);
	} else {
		while (!d.Finished()) {
			for (let out = d.Write(conn.Recv(65536)); out.length > 0; out = d.Read()) take(out);
		}
	}
	ExportAs('sha256', sha.Sum());
	ExportAs('mmh3', mmh3.Sum());
	true;
`

func encodeBody(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		require.NoError(t, err)
		w = zw
	case "":
		return data
	}
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestStreamingHashMatchesHTTPEngine(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var body []byte
	for len(body) < 6<<20 {
		body = append(body, "large compressed response body "...)
		body = append(body, byte(rng.Intn(256)))
	}

	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	for _, tc := range []struct {
		encoding string
		chunked  bool
	}{
		{"gzip", false},
		{"gzip", true},
		{"deflate", false},
		{"br", true},
		{"zstd", true},
		{"", true},
	} {
		t.Run(fmt.Sprintf("%s chunked=%v", tc.encoding, tc.chunked), func(t *testing.T) {
			encoded := encodeBody(t, tc.encoding, body)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				if !tc.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
					_, _ = w.Write(encoded)
					return
				}
				// Flushing before the handler returns makes the body chunked.
				for rest := encoded; len(rest) > 0; {
					n := min(len(rest), 50000)
					_, _ = w.Write(rest[:n])
					w.(http.Flusher).Flush()
					rest = rest[n:]
				}
			}))
			defer server.Close()

			client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			if tc.chunked {
				require.Equal(t, []string{"chunked"}, resp.TransferEncoding)
			}
			chain := httputil.NewResponseChain(resp, 64<<20)
			defer chain.Close()
			require.NoError(t, chain.Fill())
			require.Equal(t, len(body), chain.Body().Len(), "the engine must decode the whole body")
			engineBody := map[string]interface{}{"body": chain.BodyString()}
			wantSha, err := dsl.EvalExpr("sha256(body)", engineBody)
			require.NoError(t, err)
			wantMmh3, err := dsl.EvalExpr("mmh3(body)", engineBody)
			require.NoError(t, err)

			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			script := fmt.Sprintf(streamHashScript, serverURL.Host)
			compiled, err := SourceAutoMode(script, false)
			require.NoError(t, err)
			result, err := New().ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
				ExecutionId:     executionID,
				Source:          &script,
				TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: 20 * time.Second},
			})
			require.NoError(t, err)
			require.Equal(t, fmt.Sprint(wantSha), result["sha256"])
			require.Equal(t, fmt.Sprint(wantMmh3), result["mmh3"])
		})
	}
}
