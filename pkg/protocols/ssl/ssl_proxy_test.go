package ssl

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
)

// startConnectProxy runs a minimal forwarding CONNECT proxy and reports the
// target of every tunnel it opens.
func startConnectProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	seen := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				seen <- req.Host
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}(conn)
		}
	}()
	return ln.Addr().String(), seen
}

func TestSSLProtocolUsesHTTPProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "https://")

	proxyAddr, seen := startConnectProxy(t)

	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "ssl-http-proxy-test"
	options.AliveHttpProxy = "http://" + proxyAddr
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	request := &Request{Address: "{{Host}}:{{Port}}"}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-ssl-proxy",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), target)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NotEmpty(t, gotEvent)

	select {
	case host := <-seen:
		require.Equal(t, target, host)
	default:
		t.Fatal("ssl request did not go through the http proxy")
	}
}

func TestSSLOpenSSLModeFallsBackWithProxy(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "ssl-openssl-proxy-test"
	options.AliveSocksProxy = "socks5://127.0.0.1:1080"
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	request := &Request{Address: "{{Host}}:{{Port}}", ScanMode: "openssl"}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-ssl-openssl-proxy",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))
	require.Equal(t, "auto", request.ScanMode)
}

// TestSSLProxyNeverRunsOpenSSL makes both Go TLS backends fail while an openssl
// binary is available, and checks that the binary is never started, because
// s_client would dial the target directly and bypass the proxy.
func TestSSLProxyNeverRunsOpenSSL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the openssl binary")
	}
	marker := filepath.Join(t.TempDir(), "openssl-ran")
	fake := filepath.Join(t.TempDir(), "openssl")
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o700))
	// set the path directly: UseOpenSSLBinary runs "openssl version" and
	// exits the process when that fails
	previous := openssl.BinaryPath
	openssl.BinaryPath = fake
	t.Cleanup(func() { openssl.BinaryPath = previous })

	// a plain tcp server never completes a tls handshake
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			conn, err := plain.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	proxyAddr, _ := startConnectProxy(t)

	for _, mode := range []string{"auto", "openssl"} {
		t.Run(mode, func(t *testing.T) {
			options := testutils.DefaultOptions.Copy()
			options.ExecutionId = "ssl-no-openssl-" + mode
			options.AliveHttpProxy = "http://" + proxyAddr
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			request := &Request{Address: "{{Host}}:{{Port}}", ScanMode: mode}
			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   "testing-ssl-no-openssl",
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
			})
			require.NoError(t, request.Compile(executerOpts))
			require.NotNil(t, request.tlsxFallback, "ctls to ztls fallback expected behind a proxy")

			ctxArgs := contextargs.NewWithInput(context.Background(), plain.Addr().String())
			err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {})
			require.Error(t, err)
			require.NoFileExists(t, marker, "openssl s_client must not run behind a proxy")
		})
	}
}

func TestSSLNoProxyKeepsAutoMode(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "ssl-no-proxy-auto"
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	request := &Request{Address: "{{Host}}:{{Port}}"}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-ssl-no-proxy",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))
	require.Nil(t, request.tlsxFallback)
}
