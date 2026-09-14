package mssql

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

func TestIsMssqlTreatsProtocolMismatchAsNegative(t *testing.T) {
	ok, err := isMssqlResult(fmt.Errorf("%w: unexpected TDS type", errNotMssql))
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = isMssqlResult(errors.New("connection refused"))
	require.Error(t, err)
	require.False(t, ok)

	ok, err = isMssqlResult(nil)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestFingerprintMarksInvalidPacketAsNotMssql(t *testing.T) {
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
		// Invalid TDS type so parsePreloginResponse fails and fingerprintMssql
		// must wrap with errNotMssql.
		_, err = conn.Write([]byte{0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00})
		errCh <- err
	}()

	execID := "mssql-fingerprint-invalid-packet"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	_, err = fingerprintMssql(context.Background(), execID, host, port)
	require.Error(t, err)
	require.True(t, errors.Is(err, errNotMssql))

	ok, resultErr := isMssqlResult(err)
	require.NoError(t, resultErr)
	require.False(t, ok)
	require.NoError(t, <-errCh)
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
