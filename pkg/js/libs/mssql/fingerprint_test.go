package mssql

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func samplePreloginResponse() []byte {
	body := []byte{
		0x00, 0x00, 0x1f, 0x00, 0x06, // VERSION
		0x01, 0x00, 0x25, 0x00, 0x01, // ENCRYPTION
		0x02, 0x00, 0x26, 0x00, 0x01, // INSTOPT
		0x03, 0x00, 0x27, 0x00, 0x00, // THREADID
		0x04, 0x00, 0x27, 0x00, 0x01, // MARS
		0x05, 0x00, 0x28, 0x00, 0x00, // TRACEID
		0xff,
		0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // 15.0.2000
		0x02, // ENCRYPT_NOT_SUP
		0x00, // instance matches
		0x01, // MARS on
	}
	header := []byte{0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	binary.BigEndian.PutUint16(header[2:4], uint16(8+len(body)))
	return append(header, body...)
}

func TestParsePreloginResponse(t *testing.T) {
	parsed, err := parsePreloginResponse(samplePreloginResponse())
	require.NoError(t, err)
	require.Equal(t, "15.0.2000", parsed.Version)
	require.Equal(t, 15, parsed.MajorVersion)
	require.Equal(t, 0, parsed.MinorVersion)
	require.Equal(t, 2000, parsed.BuildNumber)
	require.Equal(t, int(encryptNotSup), parsed.Encryption)
	require.Equal(t, "ENCRYPT_NOT_SUP", parsed.EncryptionMode)
	require.True(t, parsed.Mars)
	require.True(t, parsed.InstanceMatches)
}

func TestParsePreloginResponseRejectsBadType(t *testing.T) {
	pkt := samplePreloginResponse()
	pkt[0] = 0x12
	_, err := parsePreloginResponse(pkt)
	require.Error(t, err)
}

func TestPreloginRoundTripMockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(preLoginRequest))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		_, err = conn.Write(samplePreloginResponse())
		errCh <- err
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(preLoginRequest)
	require.NoError(t, err)

	header := make([]byte, 8)
	_, err = io.ReadFull(conn, header)
	require.NoError(t, err)
	packetLen := int(binary.BigEndian.Uint16(header[2:4]))
	body := make([]byte, packetLen-8)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)

	parsed, err := parsePreloginResponse(append(header, body...))
	require.NoError(t, err)
	require.Equal(t, "15.0.2000", parsed.Version)
	require.NoError(t, <-errCh)
}
