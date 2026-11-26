package compiler

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// TestNetOpenTLSWithOptionsRequire proves a JS object literal reaches
// net.OpenTLSWithOptions as TLSOptions and that the negotiated ALPN protocol
// and the HTTP response protocol are visible to templates.
func TestNetOpenTLSWithOptionsRequire(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	executionID := "tls-alpn-require-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	script := fmt.Sprintf(`
		const net = require('nuclei/net');
		const http = require('nuclei/http');
		const h2 = net.OpenTLSWithOptions('tcp', %[1]q, {ALPN: ['h2'], MaxVersion: 'tls12'});
		const h1 = net.OpenTLSWithOptions('tcp', %[1]q, {ALPN: ['http/1.1']});
		const opts = new net.TLSOptions();
		opts.ALPN = ['h2', 'http/1.1'];
		const viaClass = net.OpenTLSWithOptions('tcp', %[1]q, opts);
		ExportAs('h2', h2.NegotiatedProtocol());
		ExportAs('h2version', h2.TLSVersion());
		ExportAs('h1', h1.NegotiatedProtocol());
		ExportAs('viaClass', viaClass.NegotiatedProtocol());
		h2.Close(); h1.Close(); viaClass.Close();
		ExportAs('proto', http.Get(%[2]q).Proto);
		true;
	`, srv.Listener.Addr().String(), srv.URL+"/")

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)

	result, err := New().ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: executionID,
		Source:      &script,
		TimeoutVariants: &types.Timeouts{
			JsCompilerExecutionTimeout: 10 * time.Second,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "h2", result["h2"])
	require.Equal(t, "TLS 1.2", result["h2version"])
	require.Equal(t, "http/1.1", result["h1"])
	require.Equal(t, "h2", result["viaClass"])
	require.Equal(t, "HTTP/2.0", result["proto"])
}

// TestNetHTTP2PingOverTLSRequire proves a JS template can speak raw HTTP/2
// frames over TLS after negotiating ALPN h2: it sends the connection preface,
// SETTINGS and a PING, then reads frames until the server ACKs the PING.
func TestNetHTTP2PingOverTLSRequire(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	executionID := "h2-ping-require-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	script := fmt.Sprintf(`
		const net = require('nuclei/net');
		const conn = net.OpenTLSWithOptions('tcp', %q, {ALPN: ['h2']});
		ExportAs('alpn', conn.NegotiatedProtocol());

		const preface = '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a';
		const settings = '000000040000000000';
		const pingPayload = [0x6e, 0x75, 0x63, 0x6c, 0x65, 0x69, 0x32, 0x30]; // "nuclei20"
		const ping = '000008060000000000' + pingPayload.map(b => b.toString(16).padStart(2, '0')).join('');
		conn.SendHex(preface + settings + ping);

		// RecvFull returns raw bytes; RecvFullHex returns a hex.Dump, not plain hex.
		let acked = false;
		const seen = [];
		for (let i = 0; i < 10 && !acked; i++) {
			const header = new Uint8Array(conn.RecvFull(9));
			const length = (header[0] << 16) | (header[1] << 8) | header[2];
			const type = header[3];
			const flags = header[4];
			const payload = length > 0 ? new Uint8Array(conn.RecvFull(length)) : new Uint8Array(0);
			seen.push(type + ':' + flags);
			if (type === 6 && (flags & 1) === 1 && payload.length === 8 &&
				pingPayload.every((v, idx) => payload[idx] === v)) {
				acked = true;
			}
		}
		conn.Close();
		ExportAs('acked', acked);
		ExportAs('seen', seen.join(','));
		true;
	`, srv.Listener.Addr().String())

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)

	result, err := New().ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: executionID,
		Source:      &script,
		TimeoutVariants: &types.Timeouts{
			JsCompilerExecutionTimeout: 10 * time.Second,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "h2", result["alpn"])
	require.Equal(t, "true", fmt.Sprint(result["acked"]), "frames seen (type:flags): %v", result["seen"])
}
