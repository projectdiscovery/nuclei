package kerberos

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// serveKDCTCP is a minimal fake KDC that:
// 1. Reads the full framed Kerberos request from the client.
// 2. Writes a 4-byte big-endian length header containing bodyLen.
// 3. If bodyLen <= maxKDCResponseSize, writes exactly bodyLen bytes of body.
//    For oversized values, only the header is sent (simulating a rogue peer).
func serveKDCTCP(ln net.Listener, bodyLen uint32) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Drain the client's framed Kerberos request (4-byte length + body).
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint32(hdr)
	if msgLen > 0 && msgLen < 65536 {
		body := make([]byte, msgLen)
		_, _ = io.ReadFull(conn, body)
	}

	// Send the response length header.
	rhdr := make([]byte, 4)
	binary.BigEndian.PutUint32(rhdr, bodyLen)
	_, _ = conn.Write(rhdr)

	// Only write the body for valid sizes; for oversized we expect the client
	// to reject the size before reading anything.
	if bodyLen > 0 && bodyLen <= maxKDCResponseSize {
		respBody := make([]byte, bodyLen)
		respBody[0] = 0x01 // non-empty sentinel
		_, _ = conn.Write(respBody)
	}
}

// TestSendTCP_OversizedResponseRejected verifies that sendTCP returns an error
// when a spoofed KDC advertises a response body larger than maxKDCResponseSize,
// rather than allocating that many bytes and causing an OOM.
//
// Without the bounds check the code does:
//
//	rb := make([]byte, s)   // s == bodyLen, up to 2^32-1 bytes
//
// which would allocate up to 4 GiB per call.
func TestSendTCP_OversizedResponseRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	oversized := uint32(maxKDCResponseSize + 1)
	go serveKDCTCP(ln, oversized)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	// Set a generous timeout so the test does not hang.
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = sendTCP(tcpConn, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for oversized KDC response, got nil")
	}
	t.Logf("correctly rejected oversized response: %v", err)
}

// TestSendTCP_SmallValidResponseSucceeds confirms that sendTCP succeeds when
// the KDC returns a small, valid body.
func TestSendTCP_SmallValidResponseSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	validLen := uint32(32)
	go serveKDCTCP(ln, validLen)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))

	resp, err := sendTCP(tcpConn, []byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error for valid %d-byte KDC response: %v", validLen, err)
	}
	if len(resp) != int(validLen) {
		t.Errorf("expected %d bytes, got %d", validLen, len(resp))
	}
}
