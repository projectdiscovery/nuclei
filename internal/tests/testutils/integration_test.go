package testutils

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestCloseConnUnreadInput checks that the client reads the reply and then a
// clean EOF when the server did not read all of the request. A plain close
// sends a RST here, and on Windows the RST drops the reply.
func TestCloseConnUnreadInput(t *testing.T) {
	handled := make(chan struct{})
	server := NewTCPServer(nil, 0, func(conn net.Conn) {
		defer close(handled)
		defer CloseConn(conn)

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("PONG"))
	})
	defer server.Close()

	conn, err := net.Dial("tcp", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		t.Fatal(err)
	}
	// let the server close before the client reads, as in the Windows failure
	time.Sleep(200 * time.Millisecond)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after server close: %v", err)
	}
	if string(data) != "PONG" {
		t.Fatalf("got %q, want %q", data, "PONG")
	}
	_ = conn.Close()
	<-handled
}
