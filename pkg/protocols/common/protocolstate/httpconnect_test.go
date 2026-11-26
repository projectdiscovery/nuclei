package protocolstate

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// serve accepts connections on a local listener and runs handle for each one.
// Cleanup closes every connection and waits for the handlers to return, so no
// goroutine outlives the test.
func serve(t *testing.T, handle func(conn net.Conn, track func(net.Conn))) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	track := func(c net.Conn) {
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			track(conn)
			wg.Add(1)
			go func() {
				defer wg.Done()
				handle(conn, track)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

// startConnectProxy runs a minimal CONNECT proxy that answers with status and
// reports each request it gets.
func startConnectProxy(t *testing.T, status int) (string, <-chan *http.Request) {
	t.Helper()
	seen := make(chan *http.Request, 8)
	addr := serve(t, func(conn net.Conn, track func(net.Conn)) {
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		seen <- req
		if status != http.StatusOK {
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", status, http.StatusText(status))
			return
		}
		upstream, err := net.Dial("tcp", req.Host)
		if err != nil {
			return
		}
		track(upstream)
		defer func() { _ = upstream.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, conn)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	})
	return addr, seen
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	return serve(t, func(conn net.Conn, _ func(net.Conn)) {
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	})
}

func TestHTTPConnectDialerTunnels(t *testing.T) {
	proxyAddr, seen := startConnectProxy(t, http.StatusOK)
	target := startEchoServer(t)

	d, err := newHTTPConnectDialer("http://user:pass@"+proxyAddr, &net.Dialer{}, 5*time.Second)
	require.NoError(t, err)

	conn, err := d.DialContext(context.Background(), "tcp", target)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	req := <-seen
	require.Equal(t, http.MethodConnect, req.Method)
	require.Equal(t, target, req.Host)
	require.Equal(t, "Basic dXNlcjpwYXNz", req.Header.Get("Proxy-Authorization"))

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))
}

func TestHTTPConnectDialerRefused(t *testing.T) {
	proxyAddr, _ := startConnectProxy(t, http.StatusProxyAuthRequired)

	d, err := newHTTPConnectDialer("http://"+proxyAddr, &net.Dialer{}, 5*time.Second)
	require.NoError(t, err)

	_, err = d.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	require.ErrorContains(t, err, "407")
}

func TestHTTPConnectDialerRejectsInvalid(t *testing.T) {
	_, err := newHTTPConnectDialer("socks5://127.0.0.1:1080", &net.Dialer{}, time.Second)
	require.Error(t, err)

	d, err := newHTTPConnectDialer("http://127.0.0.1:8080", &net.Dialer{}, time.Second)
	require.NoError(t, err)
	_, err = d.DialContext(context.Background(), "udp", "127.0.0.1:53")
	require.Error(t, err)
}

// startTLSConnectProxy runs a CONNECT proxy behind a self-signed certificate.
func startTLSConnectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		_, _ = io.WriteString(rw, "HTTP/1.1 200 Connection established\r\n\r\n")
		_ = rw.Flush()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		<-done
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPConnectDialerVerifiesProxyCertificate(t *testing.T) {
	proxy := startTLSConnectProxy(t)
	target := startEchoServer(t)

	// the self-signed proxy certificate is not trusted, so no credentials are sent
	d, err := newHTTPConnectDialer("https://user:pass@"+proxy.Listener.Addr().String(), &net.Dialer{}, 5*time.Second)
	require.NoError(t, err)
	_, err = d.DialContext(context.Background(), "tcp", target)
	require.ErrorContains(t, err, "could not establish TLS with proxy")

	// trusting the proxy certificate lets the tunnel through
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	d.tlsConfig = &tls.Config{RootCAs: roots}
	conn, err := d.DialContext(context.Background(), "tcp", target)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))
}

func TestHTTPConnectDialerReportsTargetAddress(t *testing.T) {
	proxyAddr, _ := startConnectProxy(t, http.StatusOK)
	target := startEchoServer(t)

	d, err := newHTTPConnectDialer("http://"+proxyAddr, &net.Dialer{}, 5*time.Second)
	require.NoError(t, err)
	conn, err := d.DialContext(context.Background(), "tcp", target)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.Equal(t, target, conn.RemoteAddr().String())
	require.NotEqual(t, proxyAddr, conn.RemoteAddr().String())
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)

	require.Equal(t, "example.com:443", tunnelAddr("example.com:443").String())
}
