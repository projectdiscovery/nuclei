package net

import (
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// dataWithErrConn returns its payload and err from the same Read call, like
// crypto/tls does when a close_notify follows the last record.
type dataWithErrConn struct {
	net.Conn
	payload []byte
	err     error
	reads   int
}

func (c *dataWithErrConn) Read(b []byte) (int, error) {
	c.reads++
	if c.payload != nil {
		n := copy(b, c.payload)
		c.payload = nil
		return n, c.err
	}
	return 0, c.err
}

func (c *dataWithErrConn) SetDeadline(time.Time) error { return nil }
func (c *dataWithErrConn) Close() error                { return nil }

func TestRecvReturnsDataReadWithError(t *testing.T) {
	fc := &dataWithErrConn{payload: []byte("last-frame"), err: io.EOF}
	c := &NetConn{conn: fc, timeout: time.Second}

	got, err := c.Recv(64)
	require.NoError(t, err)
	require.Equal(t, "last-frame", string(got))

	// The error is reported on the next call without reading again.
	got, err = c.Recv(64)
	require.Error(t, err)
	require.ErrorIs(t, err, io.EOF)
	require.Empty(t, got)
	require.Equal(t, 1, fc.reads)

	// After that, Recv reads from the connection again.
	_, err = c.Recv(64)
	require.Error(t, err)
	require.Equal(t, 2, fc.reads)
}

func TestRecvStringReturnsDataReadWithError(t *testing.T) {
	c := &NetConn{conn: &dataWithErrConn{payload: []byte("bye"), err: io.EOF}, timeout: time.Second}

	got, err := c.RecvString(64)
	require.NoError(t, err)
	require.Equal(t, "bye", got)

	_, err = c.RecvString(64)
	require.ErrorIs(t, err, io.EOF)
}

func TestRecvClearsPendingErrorOnClose(t *testing.T) {
	c := &NetConn{conn: &dataWithErrConn{payload: []byte("x"), err: io.EOF}, timeout: time.Second}
	_, err := c.Recv(8)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	require.Nil(t, c.pendingErr)
}

// TestRecvTLSDeliversBytesBeforeClose checks that the server's last bytes are
// returned before the close is reported over a real TLS connection.
func TestRecvTLSDeliversBytesBeforeClose(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()
	cert := srv.TLS.Certificates

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	want := []byte("goaway-then-close")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// One Write followed by Close: the data record and close_notify are
		// typically flushed back to back.
		_, _ = conn.Write(want)
		_ = conn.Close()
	}()

	raw, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	c := &NetConn{conn: raw, timeout: 5 * time.Second}
	defer func() { _ = c.Close() }()

	var got []byte
	for i := 0; i < 10; i++ {
		b, err := c.Recv(4096)
		got = append(got, b...)
		if err != nil {
			break
		}
	}
	require.Equal(t, string(want), string(got))
}
