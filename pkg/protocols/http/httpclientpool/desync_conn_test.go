package httpclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/retryablehttp-go"
)

type quarantineRecorder struct {
	hosts chan string
}

func newQuarantineRecorder() *quarantineRecorder {
	return &quarantineRecorder{hosts: make(chan string, 8)}
}

func (q *quarantineRecorder) record(host string) {
	select {
	case q.hosts <- host:
	default:
	}
}

func (q *quarantineRecorder) await(t *testing.T) string {
	t.Helper()
	select {
	case host := <-q.hosts:
		return host
	case <-time.After(5 * time.Second):
		t.Fatal("idle leftover never quarantined the host")
		return ""
	}
}

func (q *quarantineRecorder) requireQuiet(t *testing.T) {
	t.Helper()
	select {
	case host := <-q.hosts:
		t.Fatalf("healthy traffic was quarantined: %s", host)
	default:
	}
}

func trackedDialer(record func(string)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return newDesyncConn(conn, addr, record), nil
	}
}

func trackedTLSDialer(record func(string)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var dialer net.Dialer
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return newDesyncConn(conn, addr, record), nil
	}
}

func countingClient(t *testing.T, transport *http.Transport) *http.Client {
	t.Helper()
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: &connTrackingTransport{base: transport}}
}

// surplusHandler answers the first request, then emits a leftover response timed
// to land while the second request is outstanding. net/http attributes that
// leftover to the second request. The genuine reply then arrives with nothing
// outstanding, which is the idle-byte signal.
func surplusHandler() http.HandlerFunc {
	const (
		straySentAfter   = 50 * time.Millisecond
		realReplyDelayed = 400 * time.Millisecond
		stale            = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Tag: stale\r\n\r\nstale"
	)
	answer := func(exchange int) string {
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Tag: ok-%d\r\n\r\nbody%d", exchange, exchange)
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		if _, err := io.WriteString(conn, answer(1)); err != nil {
			return
		}
		go func() {
			time.Sleep(straySentAfter)
			_, _ = io.WriteString(conn, stale)
		}()

		for exchange := 2; ; exchange++ {
			req, err := http.ReadRequest(buffered.Reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			time.Sleep(realReplyDelayed)
			if _, err := io.WriteString(conn, answer(exchange)); err != nil {
				return
			}
		}
	}
}

func requireSurplusDetected(t *testing.T, server *httptest.Server, transport *http.Transport) {
	t.Helper()
	client := countingClient(t, transport)
	for range 2 {
		resp, err := client.Get(server.URL)
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func TestDesyncConnDetectsSurplusResponseOverHTTP(t *testing.T) {
	server := httptest.NewServer(surplusHandler())
	t.Cleanup(server.Close)

	recorder := newQuarantineRecorder()
	transport := &http.Transport{MaxIdleConnsPerHost: 1, DialContext: trackedDialer(recorder.record)}
	requireSurplusDetected(t, server, transport)

	require.Equal(t, strings.TrimPrefix(server.URL, "http://"), recorder.await(t))
}

func TestDesyncConnDetectsSurplusResponseOverHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(surplusHandler())
	t.Cleanup(server.Close)

	recorder := newQuarantineRecorder()
	transport := &http.Transport{MaxIdleConnsPerHost: 1, DialTLSContext: trackedTLSDialer(recorder.record)}
	requireSurplusDetected(t, server, transport)

	require.Equal(t, strings.TrimPrefix(server.URL, "https://"), recorder.await(t))
}

func TestDesyncConnAllowsHealthyKeepAliveTraffic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)

	recorder := newQuarantineRecorder()
	client := countingClient(t, &http.Transport{
		MaxIdleConnsPerHost: 1, DialContext: trackedDialer(recorder.record),
	})

	for range 25 {
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "ok", string(body))
		require.NoError(t, resp.Body.Close())
	}
	recorder.requireQuiet(t)
}

func TestDesyncConnIgnoresBytesWhileBusy(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	recorder := newQuarantineRecorder()
	tracked := newDesyncConn(client, "busy.test:80", recorder.record).(*desyncConn)
	t.Cleanup(func() { _ = tracked.Close() })
	tracked.markBusy()

	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") }()

	buffer := make([]byte, 128)
	_, err := tracked.Read(buffer)
	require.NoError(t, err)
	require.False(t, tracked.poisoned.Load())
	recorder.requireQuiet(t)
}

func TestDesyncConnStartsBusy(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	recorder := newQuarantineRecorder()
	tracked := newDesyncConn(client, "fresh.test:80", recorder.record).(*desyncConn)
	t.Cleanup(func() { _ = tracked.Close() })

	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }()

	buffer := make([]byte, 128)
	_, err := tracked.Read(buffer)
	require.NoError(t, err)
	require.False(t, tracked.poisoned.Load())
	recorder.requireQuiet(t)
}

func TestDesyncConnPoisonsOnBytesWhileIdleAndClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	recorder := newQuarantineRecorder()
	tracked := newDesyncConn(client, "idle.test:80", recorder.record).(*desyncConn)
	tracked.markBusy()
	tracked.markIdle()

	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nstale") }()

	buffer := make([]byte, 128)
	_, err := tracked.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "idle.test:80", recorder.await(t))
	require.True(t, tracked.poisoned.Load())

	_, err = tracked.Read(buffer)
	require.Error(t, err, "a poisoned connection must not stay usable")
}

func TestDesyncConnSkipsNegotiatedHTTP2(t *testing.T) {
	plain, _ := net.Pipe()
	t.Cleanup(func() { _ = plain.Close() })

	overHTTP2 := stubTLSConn{Conn: plain, protocol: "h2"}
	require.Equal(t, overHTTP2, newDesyncConn(overHTTP2, "h2.test:443", nil))

	overHTTP1 := stubTLSConn{Conn: plain, protocol: "http/1.1"}
	require.IsType(t, &desyncConn{}, newDesyncConn(overHTTP1, "h1.test:443", nil))
}

type stubTLSConn struct {
	net.Conn
	protocol string
}

func (s stubTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: s.protocol}
}

func TestMarkHostDesyncedStopsReuse(t *testing.T) {
	opts := newTestOptions(t, "test-desynced-host-no-reuse")
	cfg := &Configuration{}

	var conns atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	host := hostOf(t, server.URL)

	pooled, err := Get(opts, cfg, host)
	require.NoError(t, err)
	requestTwice(t, pooled, server.URL)
	require.Equal(t, int64(1), conns.Load(), "an unmarked host must reuse its connection")

	MarkHostDesynced(opts, server.URL)
	require.True(t, IsHostDesynced(opts, host))

	guarded, err := Get(opts, cfg, host)
	require.NoError(t, err)
	require.NotSame(t, pooled, guarded)

	conns.Store(0)
	requestTwice(t, guarded, server.URL)
	require.Equal(t, int64(2), conns.Load(), "a marked host must not reuse connections")
}

func TestIsHostDesyncedEmptyHost(t *testing.T) {
	opts := newTestOptions(t, "test-desync-empty-host")
	MarkHostDesynced(opts, "")
	require.False(t, IsHostDesynced(opts, ""))
}

func requestTwice(t *testing.T, client *retryablehttp.Client, target string) {
	t.Helper()
	for range 2 {
		resp, err := client.Get(target)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed.Host
}

func TestDesyncedHostKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://example.com:8443/admin?a=1", "example.com:8443"},
		{"http://example.com/", "example.com"},
		{"https://EXAMPLE.COM:443/", "example.com:443"},
		{"https://[2001:db8::1]:8443/", "[2001:db8::1]:8443"},
		{"example.com:8443", "example.com:8443"},
		{"  example.com  ", "example.com"},
		{"", ""},
	} {
		require.Equal(t, tc.want, desyncedHostKey(tc.in), tc.in)
	}
	require.NotEqual(t, desyncedHostKey("example.com:80"), desyncedHostKey("example.com:8080"))
}

func TestDesyncTrackersAreExecutionScoped(t *testing.T) {
	first := newTestOptions(t, "test-desync-scope-first")
	second := newTestOptions(t, "test-desync-scope-second")

	MarkHostDesynced(first, "example.com:443")
	require.True(t, IsHostDesynced(first, "example.com:443"))
	require.False(t, IsHostDesynced(second, "example.com:443"))
	require.Equal(t, []string{"example.com:443"}, DesyncedHosts(first))
	require.Empty(t, DesyncedHosts(second))
}
