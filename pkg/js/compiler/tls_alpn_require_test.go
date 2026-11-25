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
