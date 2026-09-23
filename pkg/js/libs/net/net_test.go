package net

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestGetTimeoutFromContext(t *testing.T) {
	t.Run("default when missing", func(t *testing.T) {
		require.Equal(t, defaultTimeout, getTimeoutFromContext(context.Background()))
	})

	t.Run("reads TcpReadTimeout", func(t *testing.T) {
		expected := 15 * time.Second
		tv := &types.Timeouts{TcpReadTimeout: expected}
		ctx := context.WithValue(context.Background(), "timeoutVariants", tv) // nolint: staticcheck
		require.Equal(t, expected, getTimeoutFromContext(ctx))
	})
}

func TestBufferedConn(t *testing.T) {
	t.Run("read drains buffered bytes first", func(t *testing.T) {
		underlying := &bytes.Buffer{}
		underlying.WriteString("hello world")

		br := bufio.NewReader(underlying)
		_, _ = br.Peek(5)

		conn := &bufferedConn{
			Conn:   &fakeConn{},
			reader: br,
		}

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "hello world", string(buf[:n]))
	})

	t.Run("read returns EOF after buffer is drained", func(t *testing.T) {
		underlying := bytes.NewBufferString("data")
		br := bufio.NewReader(underlying)
		conn := &bufferedConn{Conn: &fakeConn{}, reader: br}

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "data", string(buf[:n]))

		_, err = conn.Read(buf)
		require.ErrorIs(t, err, io.EOF)
	})
}

// directDial is a plain net.Dialer for tests (no fastdialer dependency).
var directDial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext

func TestDialHTTPProxy(t *testing.T) {
	t.Run("successful CONNECT tunnel", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		targetPayload := "hello from target"
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			_ = req.Body.Close()

			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			_, _ = conn.Write([]byte(targetPayload))
		}()

		ctx := context.Background()
		proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
		conn, err := dialHTTPProxy(ctx, directDial, proxyURL, "example.com:443", 5*time.Second)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, targetPayload, string(buf[:n]))
	})

	t.Run("proxy returns non-200 status", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			_ = req.Body.Close()
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		}()

		ctx := context.Background()
		proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
		_, err = dialHTTPProxy(ctx, directDial, proxyURL, "example.com:443", 5*time.Second)
		require.Error(t, err)
		require.Contains(t, err.Error(), "403")
	})

	t.Run("invalid proxy URL", func(t *testing.T) {
		ctx := context.Background()
		_, err := dialHTTPProxy(ctx, directDial, "://bad-url", "example.com:443", 5*time.Second)
		require.Error(t, err)
	})

	t.Run("successful HTTPS CONNECT tunnel", func(t *testing.T) {
		targetPayload := "hello from secure proxy"
		proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = rw.WriteString(targetPayload)
			_ = rw.Flush()
		}))
		defer proxy.Close()

		ctx := context.Background()
		conn, err := dialHTTPProxy(ctx, directDial, proxy.URL, "example.com:443", 5*time.Second)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, targetPayload, string(buf[:n]))
	})

	t.Run("unreachable proxy", func(t *testing.T) {
		ctx := context.Background()
		_, err := dialHTTPProxy(ctx, directDial, "http://127.0.0.1:1", "example.com:443", 1*time.Second)
		require.Error(t, err)
	})

	t.Run("proxy auth header", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		gotAuth := make(chan string, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			_ = req.Body.Close()
			gotAuth <- req.Header.Get("Proxy-Authorization")
			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}()

		proxyURL := fmt.Sprintf("http://user:secret@%s", ln.Addr().String())
		conn, err := dialHTTPProxy(context.Background(), directDial, proxyURL, "example.com:443", 5*time.Second)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		require.Equal(t, "Basic "+basicAuth(url.UserPassword("user", "secret")), <-gotAuth)
	})
}

func TestDial(t *testing.T) {
	t.Run("missing execution id", func(t *testing.T) {
		_, err := Dial(context.Background(), "tcp", "127.0.0.1:1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "executionId")
	})

	t.Run("unsupported proxy scheme fails hard", func(t *testing.T) {
		opts := &types.Options{ExecutionId: "net-dial-scheme-" + t.Name()}
		require.NoError(t, protocolstate.Init(opts))
		t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })

		ctx := context.WithValue(context.Background(), "executionId", opts.ExecutionId) // nolint: staticcheck
		ctx = context.WithValue(ctx, "proxyURL", "socks5://127.0.0.1:1080")              // nolint: staticcheck
		_, err := Dial(ctx, "tcp", "example.com:80")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported proxy scheme")
	})

	t.Run("invalid proxy url fails hard", func(t *testing.T) {
		opts := &types.Options{ExecutionId: "net-dial-invalid-" + t.Name()}
		require.NoError(t, protocolstate.Init(opts))
		t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })

		ctx := context.WithValue(context.Background(), "executionId", opts.ExecutionId) // nolint: staticcheck
		ctx = context.WithValue(ctx, "proxyURL", "://bad")                               // nolint: staticcheck
		_, err := Dial(ctx, "tcp", "example.com:80")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proxy URL")
	})

	t.Run("udp with http proxy fails hard", func(t *testing.T) {
		opts := &types.Options{ExecutionId: "net-dial-udp-" + t.Name()}
		require.NoError(t, protocolstate.Init(opts))
		t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })

		ctx := context.WithValue(context.Background(), "executionId", opts.ExecutionId) // nolint: staticcheck
		ctx = context.WithValue(ctx, "proxyURL", "http://127.0.0.1:8080")                // nolint: staticcheck
		_, err := Dial(ctx, "udp", "example.com:53")
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not support protocol")
	})

	t.Run("open through local http proxy", func(t *testing.T) {
		target, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = target.Close() }()

		go func() {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = conn.Write([]byte("pong"))
		}()

		proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = proxyLn.Close() }()

		go func() {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			_ = req.Body.Close()
			require.Equal(t, http.MethodConnect, req.Method)
			require.Equal(t, target.Addr().String(), req.Host)

			upstream, err := net.Dial("tcp", target.Addr().String())
			if err != nil {
				return
			}
			defer func() { _ = upstream.Close() }()

			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() { _, _ = io.Copy(upstream, conn) }()
			_, _ = io.Copy(conn, upstream)
		}()

		opts := &types.Options{ExecutionId: "net-dial-proxy-" + t.Name()}
		require.NoError(t, protocolstate.Init(opts))
		t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })

		ctx := context.WithValue(context.Background(), "executionId", opts.ExecutionId) // nolint: staticcheck
		ctx = context.WithValue(ctx, "proxyURL", "http://"+proxyLn.Addr().String())     // nolint: staticcheck
		ctx = context.WithValue(ctx, "timeoutVariants", &types.Timeouts{TcpReadTimeout: 5 * time.Second}) // nolint: staticcheck

		nconn, err := Open(ctx, "tcp", target.Addr().String())
		require.NoError(t, err)
		defer func() { _ = nconn.Close() }()

		buf := make([]byte, 16)
		n, err := nconn.conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "pong", string(buf[:n]))
	})
}

func TestRedactProxyURL(t *testing.T) {
	require.Equal(t, "http://proxy.example.com:8080", redactProxyURL("http://user:pass@proxy.example.com:8080"))
	require.Equal(t, "http://proxy.example.com:8080", redactProxyURL("http://proxy.example.com:8080"))
	require.Equal(t, "<invalid proxy URL>", redactProxyURL("://bad-url"))
}

// fakeConn is a minimal net.Conn for testing bufferedConn.
type fakeConn struct{ net.Conn }

func (f *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (f *fakeConn) Write([]byte) (int, error)        { return 0, nil }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
