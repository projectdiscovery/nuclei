package kerberos

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSendTCPReadsSplitLengthPrefix(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	body := []byte("kdc-reply")
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, uint32(len(body)))
		_, _ = conn.Write(prefix[:2])
		time.Sleep(20 * time.Millisecond)
		_, _ = conn.Write(prefix[2:])
		_, _ = conn.Write(body)
	}()

	conn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	got, err := sendTCP(conn, []byte("request"))
	if err != nil {
		t.Fatalf("sendTCP failed: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected %q, got %q", body, got)
	}
}
