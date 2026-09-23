package httpclientpool

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
)

// desyncConn watches for bytes that arrive from a server while the connection is
// not serving any request. A server has nothing to answer at that point, so
// whatever it sends belongs to an earlier exchange.
//
// Idleness comes from net/http: GotConn fires when a request takes the
// connection and PutIdleConn fires when it returns to the pool. Bytes in that
// window are unsolicited by the same criterion net/http uses internally. The
// check is one atomic load in Read, identical over plaintext and TLS because
// the wrapper sits above the handshake: only decrypted application data
// reaches it. Below the handshake a session ticket or a close_notify alert on
// an idle connection would read as a leftover and quarantine a healthy host.
//
// net/http already closes a connection when it notices this, but only logs it.
// Observing it here is what lets the pool stop reusing connections to that host.
// A leftover that arrives while a request is outstanding is indistinguishable
// from that request's real reply, so this cannot save the first wrong response.
// Closing and quarantining only stops the host from doing it again.
type desyncConn struct {
	net.Conn
	host      string
	onPoison  func(host string)
	idle      atomic.Bool
	poisoned  atomic.Bool
	closeOnce sync.Once
}

func newDesyncConn(conn net.Conn, addr string, onPoison func(host string)) net.Conn {
	if conn == nil || negotiatedHTTP2(conn) {
		return conn
	}
	return &desyncConn{
		Conn:     conn,
		host:     desyncedHostKey(addr),
		onPoison: onPoison,
	}
}

func (c *desyncConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.idle.Load() {
		c.poison()
	}
	return n, err
}

func (c *desyncConn) markBusy() {
	c.idle.Store(false)
}

func (c *desyncConn) markIdle() {
	c.idle.Store(true)
}

func (c *desyncConn) Close() error {
	c.idle.Store(false)
	return c.Conn.Close()
}

// tlsState reports the handshake state of the wrapped connection when there is
// one. Go 1.26 net/http only reads TLS metadata from a concrete *tls.Conn
// returned by DialTLSContext, so a tracked connection leaves resp.TLS empty
// and connTrackingTransport fills it from here.
func (c *desyncConn) tlsState() (tls.ConnectionState, bool) {
	handshaked, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return tls.ConnectionState{}, false
	}
	state := handshaked.ConnectionState()
	if !state.HandshakeComplete {
		return tls.ConnectionState{}, false
	}
	return state, true
}

func (c *desyncConn) poison() {
	if !c.poisoned.CompareAndSwap(false, true) {
		return
	}
	c.idle.Store(false)
	if c.onPoison != nil {
		c.onPoison(c.host)
	}
	c.closeOnce.Do(func() { _ = c.Conn.Close() })
}

func negotiatedHTTP2(conn net.Conn) bool {
	handshaked, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return false
	}
	return handshaked.ConnectionState().NegotiatedProtocol == "h2"
}
