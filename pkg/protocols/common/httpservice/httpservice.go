// Package httpservice answers, once per scan and per host:port, whether that
// port speaks HTTP.
//
// It exists for one decision: a template that can only speak a dedicated
// non-HTTP protocol (SMB, SSH, MySQL, ...) cannot produce a finding on a port
// that answers HTTP, so running it there only costs time and sends garbage to
// the target. The answer must come from evidence, never from the scheme the
// operator typed: "http://host:22" still gets its SSH templates unless port 22
// really answers HTTP.
//
// Every failure (policy denial, refusal, timeout, TLS error, a reply that is
// not an HTTP status line) reports false, so a caller that skips work only on
// true always fails open.
package httpservice

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// DefaultTimeout bounds one probe: connect, request and the first bytes of the
// reply.
const DefaultTimeout = 3 * time.Second

// Dialer opens a connection. It matches fastdialer's Dial and DialTLS.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Cache memoizes probe results for one scan execution.
type Cache struct {
	executionID string
	timeout     time.Duration

	// dial and dialTLS default to the scan's fastdialer, which enforces the
	// network policy. Tests replace them.
	dial    Dialer
	dialTLS Dialer
	allowed func(hostPort string) bool

	group  singleflight.Group
	mu     sync.RWMutex
	seen   map[string]bool
	probes atomic.Uint64
}

// New returns a cache bound to the dialers and network policy of executionID.
func New(executionID string) *Cache {
	c := &Cache{
		executionID: executionID,
		timeout:     DefaultTimeout,
		seen:        make(map[string]bool),
	}
	c.allowed = func(hostPort string) bool {
		return protocolstate.IsHostAllowed(executionID, hostPort)
	}
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := protocolstate.GetDialersWithId(executionID)
		if d == nil || d.Fastdialer == nil {
			return nil, errNoDialer
		}
		return d.Fastdialer.Dial(ctx, network, address)
	}
	c.dialTLS = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := protocolstate.GetDialersWithId(executionID)
		if d == nil || d.Fastdialer == nil {
			return nil, errNoDialer
		}
		return d.Fastdialer.DialTLS(ctx, network, address)
	}
	return c
}

type probeError string

func (e probeError) Error() string { return string(e) }

const errNoDialer = probeError("httpservice: no dialer for this execution")

// SpeaksHTTP reports whether hostPort answered an HTTP request with an HTTP
// status line. useTLS selects a TLS connection. The first call for a key
// probes; concurrent and later calls share that result.
func (c *Cache) SpeaksHTTP(ctx context.Context, hostPort string, useTLS bool) bool {
	if c == nil || hostPort == "" {
		return false
	}
	key := hostPort
	if useTLS {
		key = "tls://" + hostPort
	}
	c.mu.RLock()
	v, ok := c.seen[key]
	c.mu.RUnlock()
	if ok {
		return v
	}
	res, _, _ := c.group.Do(key, func() (any, error) {
		got := c.probe(ctx, hostPort, useTLS)
		c.mu.Lock()
		c.seen[key] = got
		c.mu.Unlock()
		return got, nil
	})
	return res.(bool)
}

// Reset forgets every probe result, so the next scan probes again.
func (c *Cache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.seen = make(map[string]bool)
	c.mu.Unlock()
}

// Probes returns how many network probes were sent (tests and stats).
func (c *Cache) Probes() uint64 {
	if c == nil {
		return 0
	}
	return c.probes.Load()
}

func (c *Cache) probe(ctx context.Context, hostPort string, useTLS bool) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" {
		return false
	}
	if c.allowed != nil && !c.allowed(hostPort) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	dial := c.dial
	if useTLS {
		dial = c.dialTLS
	}
	if dial == nil {
		return false
	}
	c.probes.Add(1)
	conn, err := dial(ctx, "tcp", hostPort)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return false
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return isHTTPStatusLine(buf)
}

// isHTTPStatusLine reports whether b starts like an HTTP/1.x status line.
func isHTTPStatusLine(b []byte) bool {
	return bytes.HasPrefix(b, []byte("HTTP/1."))
}
