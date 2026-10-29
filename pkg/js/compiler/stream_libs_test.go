package compiler

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// A template reads a gzip response over nuclei/net in 64 KB Recv calls and
// hashes the decoded body as it goes. Its sum must equal the sha256 of the
// whole decoded body.
func TestStreamingDecodeAndHashOverRecv(t *testing.T) {
	body := bytes.Repeat([]byte("large compressed response body "), 200000) // ~6 MB
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(body)
	require.NoError(t, zw.Close())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 4096))
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", gz.Len())
		_, _ = conn.Write(gz.Bytes())
	}()

	executionID := t.Name()
	options := &types.Options{ExecutionId: executionID}
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	script := fmt.Sprintf(`
		const net = require('nuclei/net');
		const compress = require('nuclei/compress');
		const hash = require('nuclei/hash');

		const conn = net.Open('tcp', %q);
		conn.Send('GET / HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip\r\n\r\n');
		let head = '';
		while (!head.endsWith('\r\n\r\n')) head += conn.RecvString(1);
		const length = parseInt(head.match(/Content-Length: (\d+)/)[1]);
		const encoding = head.match(/Content-Encoding: (\S+)/)[1];

		const decoder = compress.NewDecoder(encoding);
		const h = hash.New('sha256');
		let decoded = 0;
		const take = (out) => { decoded += out.length; h.Write(out); };
		for (let read = 0; read < length; ) {
			const chunk = conn.Recv(65536);
			read += chunk.length;
			for (let out = decoder.Write(chunk); out.length > 0; out = decoder.Read()) take(out);
		}
		for (let out = decoder.Close(); out.length > 0; out = decoder.Read()) take(out);
		ExportAs('sum', h.Sum());
		ExportAs('decoded', decoded);
		true;
	`, listener.Addr().String())

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)
	result, err := New().ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId:     executionID,
		Source:          &script,
		TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: 20 * time.Second},
	})
	require.NoError(t, err)

	want := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(want[:]), result["sum"])
	require.Equal(t, fmt.Sprint(len(body)), result["decoded"])
}
