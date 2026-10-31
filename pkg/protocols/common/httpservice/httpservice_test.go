package httpservice

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testCache() *Cache {
	d := &net.Dialer{}
	return &Cache{
		timeout: time.Second,
		seen:    make(map[string]bool),
		allowed: func(string) bool { return true },
		dial:    d.DialContext,
		dialTLS: d.DialContext, // TLS is not exercised in these tests
	}
}

func TestSpeaksHTTPOnHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := testCache()
	if !c.SpeaksHTTP(context.Background(), srv.Listener.Addr().String(), false) {
		t.Fatal("an HTTP server must be reported as HTTP")
	}
}

// A service that sends its own banner (SSH, SMTP, FTP, ...) is not HTTP.
func TestBannerServiceIsNotHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = conn.Close()
		}
	}()
	c := testCache()
	if c.SpeaksHTTP(context.Background(), ln.Addr().String(), false) {
		t.Fatal("an SSH banner must not be reported as HTTP")
	}
}

// A service that never answers must not be reported as HTTP (fail open), and
// the probe must respect its timeout.
func TestSilentServiceFailsOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn) // hold it open, never answer
			mu.Unlock()
		}
	}()
	c := testCache()
	c.timeout = 200 * time.Millisecond
	start := time.Now()
	if c.SpeaksHTTP(context.Background(), ln.Addr().String(), false) {
		t.Fatal("a silent service must not be reported as HTTP")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the probe did not respect its timeout")
	}
	mu.Lock()
	for _, c := range conns {
		_ = c.Close()
	}
	mu.Unlock()
}

func TestClosedPortFailsOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if testCache().SpeaksHTTP(context.Background(), addr, false) {
		t.Fatal("a closed port must not be reported as HTTP")
	}
}

// The network policy is checked before any dial.
func TestPolicyDenialFailsOpenWithoutDialing(t *testing.T) {
	c := testCache()
	c.allowed = func(string) bool { return false }
	dialed := false
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = true
		return nil, errNoDialer
	}
	if c.SpeaksHTTP(context.Background(), "127.0.0.1:1", false) {
		t.Fatal("a denied host must not be reported as HTTP")
	}
	if dialed {
		t.Fatal("a denied host must not be dialed")
	}
}

// One probe per host:port, however many templates ask concurrently.
func TestProbeIsMemoized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := testCache()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !c.SpeaksHTTP(context.Background(), srv.Listener.Addr().String(), false) {
				t.Error("expected HTTP")
			}
		}()
	}
	wg.Wait()
	if got := c.Probes(); got != 1 {
		t.Fatalf("probes=%d want 1", got)
	}
}

func TestNilCache(t *testing.T) {
	var c *Cache
	if c.SpeaksHTTP(context.Background(), "127.0.0.1:80", false) {
		t.Fatal("a nil cache must report false")
	}
}

func TestResetForgetsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := testCache()
	addr := srv.Listener.Addr().String()
	c.SpeaksHTTP(context.Background(), addr, false)
	c.Reset()
	c.SpeaksHTTP(context.Background(), addr, false)
	if got := c.Probes(); got != 2 {
		t.Fatalf("after Reset the next call must probe again: probes=%d", got)
	}
}
