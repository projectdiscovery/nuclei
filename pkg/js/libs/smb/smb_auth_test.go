package smb_test

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/goja_nodejs/require"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmb"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smb"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	assert "github.com/stretchr/testify/require"
)

func TestAuthenticateSessionStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		user   string
		flags  uint16
		status uint32
		want   smb.AuthenticationResult
	}{
		{"regular", `DOMAIN\user`, 0, 0, smb.AuthenticationResult{Success: true}},
		{"guest username without guest flag", "guest", 0, 0, smb.AuthenticationResult{Success: true}},
		{"guest fallback", "unknown-user", 1, 0, smb.AuthenticationResult{Success: true, IsGuest: true}},
		{"null session", "", 2, 0, smb.AuthenticationResult{Success: true, IsNullSession: true}},
		{"both flags", "user", 3, 0, smb.AuthenticationResult{Success: true, IsGuest: true, IsNullSession: true}},
		{"unrelated flag", "user", 0x8000, 0, smb.AuthenticationResult{Success: true}},
		{"rejected credentials", "user", 0, 0xc000006d, smb.AuthenticationResult{}},
	} {
		for _, javascript := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/javascript=%v", tc.name, javascript), func(t *testing.T) {
				password := "password"
				if tc.user == "" {
					password = ""
				}
				executionID := t.Name()
				assert.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
				t.Cleanup(func() { protocolstate.Close(executionID) })
				port, done := serveAuthentication(t, tc.flags, tc.status)
				if javascript {
					vm := goja.New()
					new(require.Registry).Enable(vm)
					vm.SetContextValue("executionId", executionID)
					assert.NoError(t, vm.Set("port", port))
					assert.NoError(t, vm.Set("user", tc.user))
					assert.NoError(t, vm.Set("password", password))
					value, err := vm.RunString(`
						const client = new (require('nuclei/smb').SMBClient)();
						const result = client.Authenticate('127.0.0.1', port, user, password);
						[result.Success, result.IsGuest, result.IsNullSession];
					`)
					if tc.status != 0 {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
						assert.Equal(t, []interface{}{tc.want.Success, tc.want.IsGuest, tc.want.IsNullSession}, value.Export())
					}
				} else {
					ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
					result, err := (&smb.SMBClient{}).Authenticate(ctx, "127.0.0.1", port, tc.user, password)
					if tc.status != 0 {
						assert.Error(t, err)
						assert.Nil(t, result)
					} else {
						assert.NoError(t, err)
						assert.Equal(t, tc.want, *result)
					}
				}
				select {
				case err := <-done:
					assert.NoError(t, err)
				case <-time.After(6 * time.Second):
					t.Fatal("SMB authentication exchange did not finish")
				}
			})
		}
	}
}

func TestAuthenticateMissingExecutionID(t *testing.T) {
	for _, tc := range []struct {
		name        string
		executionID any
	}{
		{"missing", nil},
		{"wrong type", 42},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.executionID != nil {
				ctx = context.WithValue(ctx, "executionId", tc.executionID) //nolint:staticcheck
			}
			result, err := (&smb.SMBClient{}).Authenticate(ctx, "127.0.0.1", 445, "user", "password")
			assert.EqualError(t, err, "smb: missing executionId in context")
			assert.Nil(t, result)
		})
	}
}

func TestAuthenticateDeniedHost(t *testing.T) {
	const executionID = "smb-auth-denied"
	assert.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID, ExcludeTargets: []string{"127.0.0.1"}}))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	result, err := (&smb.SMBClient{}).Authenticate(ctx, "127.0.0.1", 445, "user", "password")
	assert.EqualError(t, err, protocolstate.ErrHostDenied.Msgf("127.0.0.1").Error())
	assert.Nil(t, result)
}

func TestAuthenticateCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = context.WithValue(ctx, "executionId", "smb-auth-canceled") //nolint:staticcheck
	result, err := (&smb.SMBClient{}).Authenticate(ctx, "127.0.0.1", 445, "user", "password")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
}

// serveAuthentication completes the NTLM exchange and rejects any command other
// than negotiate, session setup, and logoff. This detects share enumeration even
// when it would fail or its result would be ignored by Authenticate.
func serveAuthentication(t *testing.T, flags uint16, status uint32) (int, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		err = authenticationExchange(conn, flags, status)
		done <- errors.Join(err, conn.Close())
	}()
	return listener.Addr().(*net.TCPAddr).Port, done
}

func authenticationExchange(conn net.Conn, flags uint16, status uint32) error {
	// A minimal NTLM challenge with target-info terminator and a fixed nonce.
	challenge := make([]byte, 52)
	copy(challenge, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(challenge[8:], 2)
	binary.LittleEndian.PutUint32(challenge[20:], 0x00880205)
	copy(challenge[24:], "12345678")
	binary.LittleEndian.PutUint16(challenge[40:], 4)
	binary.LittleEndian.PutUint16(challenge[42:], 4)
	binary.LittleEndian.PutUint32(challenge[44:], 48)
	token, err := asn1.MarshalWithParams(struct {
		State asn1.Enumerated `asn1:"explicit,tag:0"`
		Token []byte          `asn1:"explicit,tag:2"`
	}{1, challenge}, "explicit,tag:1")
	if err != nil {
		return err
	}
	for step, command := range []uint16{0, 1, 1, 2} {
		request, err := readSMBPacket(conn)
		if err != nil {
			return err
		}
		if got := binary.LittleEndian.Uint16(request[12:]); got != command {
			return fmt.Errorf("step %d: unexpected SMB command %d, want %d (share access is forbidden)", step, got, command)
		}
		response := make([]byte, 64)
		copy(response, "\xfeSMB")
		binary.LittleEndian.PutUint16(response[4:], 64)
		binary.LittleEndian.PutUint16(response[12:], command)
		binary.LittleEndian.PutUint16(response[14:], 1)
		binary.LittleEndian.PutUint32(response[16:], 1) // server-to-client
		copy(response[24:32], request[24:32])           // message ID
		binary.LittleEndian.PutUint64(response[40:], 1) // session ID
		switch step {
		case 0:
			body := make([]byte, 65)
			binary.LittleEndian.PutUint16(body, 65)
			binary.LittleEndian.PutUint16(body[2:], 1) // signing enabled
			binary.LittleEndian.PutUint16(body[4:], 0x0210)
			for _, offset := range []int{28, 32, 36} {
				binary.LittleEndian.PutUint32(body[offset:], 65536)
			}
			response = append(response, body...)
		case 1, 2:
			body := make([]byte, 8)
			binary.LittleEndian.PutUint16(body, 9)
			binary.LittleEndian.PutUint16(body[4:], 72)
			if step == 1 {
				binary.LittleEndian.PutUint32(response[8:], 0xc0000016) // more processing required
				binary.LittleEndian.PutUint16(body[6:], uint16(len(token)))
				body = append(body, token...)
			} else {
				binary.LittleEndian.PutUint32(response[8:], status)
				binary.LittleEndian.PutUint16(body[2:], flags)
			}
			response = append(response, body...)
		case 3:
			// Closing the transport after logoff avoids signing a response; the
			// test server does not validate credentials or derive signing keys.
			return nil
		}
		if err := binary.Write(conn, binary.BigEndian, uint32(len(response))); err != nil {
			return err
		}
		if _, err := conn.Write(response); err != nil {
			return err
		}
		if step == 2 && status != 0 {
			_, err := readSMBPacket(conn)
			if err != io.EOF {
				return fmt.Errorf("expected connection close after rejected authentication, got %v", err)
			}
			return nil
		}
	}
	return nil
}

func readSMBPacket(conn net.Conn) ([]byte, error) {
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size < 64 || size > 65536 {
		return nil, fmt.Errorf("unexpected SMB packet size %d", size)
	}
	packet := make([]byte, size)
	_, err := io.ReadFull(conn, packet)
	return packet, err
}
