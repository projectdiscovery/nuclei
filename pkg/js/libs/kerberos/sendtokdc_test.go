package kerberos

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSendTCPReadsSplitLengthHeader checks that sendTCP reads the whole
// 4-byte length prefix when the KDC sends it in more than one segment.
func TestSendTCPReadsSplitLengthHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = listener.Close()
	}()

	reply := []byte("kerberos reply")
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		_ = conn.(*net.TCPConn).SetNoDelay(true)

		// Read the 4-byte request length and the request itself.
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			done <- err
			return
		}
		request := make([]byte, binary.BigEndian.Uint32(header))
		if _, err := io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}

		size := make([]byte, 4)
		binary.BigEndian.PutUint32(size, uint32(len(reply)))
		// Send the length prefix in two writes so the client sees a short read.
		if _, err := conn.Write(size[:2]); err != nil {
			done <- err
			return
		}
		time.Sleep(50 * time.Millisecond)
		if _, err := conn.Write(append(size[2:], reply...)); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	conn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	got, err := sendTCP(conn, []byte("request"))
	require.NoError(t, err)
	require.Equal(t, reply, got)
	require.NoError(t, <-done)
}
