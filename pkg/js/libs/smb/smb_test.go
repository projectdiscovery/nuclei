package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zgrabsmb "github.com/zmap/zgrab2/lib/smb/smb"
)

func TestUpdateSMBv1SupportPreservesNegotiatedSMB2Version(t *testing.T) {
	version := &zgrabsmb.SMBVersions{
		Major:     2,
		Minor:     1,
		VerString: "SMB 2.1",
	}
	result := &zgrabsmb.SMBLog{
		Version: version,
	}
	dial, done := newSMBv1ProbeDialer()

	updateSMBv1Support(context.Background(), result, dial)

	require.True(t, result.SupportV1)
	require.Same(t, version, result.Version)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("SMBv1 probe was not performed")
	}
}

func TestUpdateSMBv1SupportIgnoresProbeErrors(t *testing.T) {
	result := &zgrabsmb.SMBLog{}

	updateSMBv1Support(context.Background(), result, func(context.Context) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})

	require.False(t, result.SupportV1)
}

func newSMBv1ProbeDialer() (smbInfoDialFunc, <-chan error) {
	done := make(chan error, 1)
	return func(context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer close(done)
			done <- serveSMBv1Probe(serverConn)
		}()
		return clientConn, nil
	}, done
}

func serveSMBv1Probe(conn net.Conn) error {
	defer func() {
		_ = conn.Close()
	}()

	var requestSize uint32
	if err := binary.Read(conn, binary.BigEndian, &requestSize); err != nil {
		return err
	}
	request := make([]byte, requestSize)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if len(request) < 4 {
		return io.ErrUnexpectedEOF
	}
	if string(request[:4]) != zgrabsmb.ProtocolSmb {
		return errors.New("expected SMBv1 negotiate request")
	}

	response := []byte(zgrabsmb.ProtocolSmb)
	if err := binary.Write(conn, binary.BigEndian, uint32(len(response))); err != nil {
		return err
	}
	_, err := conn.Write(response)
	return err
}
