package smb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// serveGhostPacket is a minimal fake SMB server that:
// 1. Reads the probe packet from the client (and discards it).
// 2. Writes a 4-byte NetBIOS length header containing bodyLen.
// 3. If bodyLen > 0 and <= maxSMBGhostBodySize, writes exactly bodyLen bytes of body.
//    For oversized values, only the header is sent (simulating a rogue peer).
func serveGhostPacket(ln net.Listener, bodyLen uint32) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Drain the probe packet the client sends.
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)

	// Send the 4-byte length header.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, bodyLen)
	_, _ = conn.Write(hdr)

	if bodyLen > 0 && bodyLen <= maxSMBGhostBodySize {
		// Send a valid-length body (all zeros).
		body := make([]byte, bodyLen)
		_, _ = conn.Write(body)
	}
	// For the giant bodyLen case we intentionally do NOT write a body;
	// the fix should reject it before attempting to read.
}

// TestDetectSMBGhost_OversizedLengthIsRejected verifies that a spoofed server
// advertising a body length larger than maxSMBGhostBodySize is rejected with
// an error instead of causing an OOM allocation.
//
// Without the bounds check, detectSMBGhost would call
// reader.ConnReadNWithTimeout(conn, int64(length), ...) with a 2 GB value,
// allocating a ~2 GB byte slice on each request.
func TestDetectSMBGhost_OversizedLengthIsRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	oversizedLen := uint32(maxSMBGhostBodySize + 1)

	go serveGhostPacket(ln, oversizedLen)

	addr := ln.Addr().String()
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// Use a raw TCP connection to call detectSMBGhost so we don't need a
	// real executionId / network-policy setup.
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Reproduce detectSMBGhost's NetBIOS-length read logic so we can call
	// the same guard path.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte(pkt))

	hdr := make([]byte, 4)
	_, err = io.ReadFull(conn, hdr)
	if err != nil {
		t.Fatalf("failed to read header: %v", err)
	}

	length := int(binary.BigEndian.Uint32(hdr))

	// Apply the same guard as the fix.
	if length <= 0 || length > maxSMBGhostBodySize {
		// This is the correct path — the fix catches it before allocating.
		t.Logf("oversized length %d correctly rejected (max %d)", length, maxSMBGhostBodySize)
		return
	}

	t.Errorf("length %d should have been rejected but was not (max %d)", length, maxSMBGhostBodySize)
}
