//go:build integration
// +build integration

package integration_test

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

type javascriptMSSQLFingerprint struct{}

func (j *javascriptMSSQLFingerprint) Execute(filePath string) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMSSQLPreloginConn(conn)
		}
	}()

	results, err := runSignedNucleiTemplateAndGetResults(filePath, ln.Addr().String(), debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

func handleMSSQLPreloginConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	if _, err := io.ReadAtLeast(conn, buf, 8); err != nil {
		return
	}
	_, _ = conn.Write(sampleMSSQLPreloginResponse())
}

func sampleMSSQLPreloginResponse() []byte {
	body := []byte{
		0x00, 0x00, 0x1f, 0x00, 0x06,
		0x01, 0x00, 0x25, 0x00, 0x01,
		0x02, 0x00, 0x26, 0x00, 0x01,
		0x03, 0x00, 0x27, 0x00, 0x00,
		0x04, 0x00, 0x27, 0x00, 0x01,
		0x05, 0x00, 0x28, 0x00, 0x00,
		0xff,
		0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00,
		0x02,
		0x00,
		0x01,
	}
	header := []byte{0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	binary.BigEndian.PutUint16(header[2:4], uint16(8+len(body)))
	return append(header, body...)
}
