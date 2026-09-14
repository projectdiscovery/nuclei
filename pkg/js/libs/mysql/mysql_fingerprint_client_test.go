package mysql

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func initMySQLExec(t *testing.T) (context.Context, string) {
	t.Helper()
	executionID := "mysql-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	return ctx, executionID
}

// startGreetingServer serves a fixed MySQL greeting once per accepted connection.
// dialCount increments on each Accept.
func startGreetingServer(t *testing.T, packet []byte, dialCount *atomic.Int32) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if dialCount != nil {
				dialCount.Add(1)
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write(packet)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestFingerprintMySQLClientHandshake(t *testing.T) {
	t.Parallel()

	ctx, _ := initMySQLExec(t)
	host, port := startGreetingServer(t, testHandshakePacket(t), nil)

	client := &MySQLClient{}
	info, err := client.FingerprintMySQL(ctx, host, port)
	require.NoError(t, err)

	require.Equal(t, host, info.Host)
	require.Equal(t, port, info.Port)
	require.Equal(t, "mysql", info.Protocol)
	require.Equal(t, "tcp", info.Transport)
	require.False(t, info.TLS)
	require.Equal(t, "8.0.28", info.Version)
	require.Equal(t, 10, info.ProtocolVersion)
	require.Equal(t, uint32(11), info.ThreadID)
	require.Equal(t, "caching_sha2_password", info.AuthPluginName)
	require.NotEmpty(t, info.Salt)
	require.NotZero(t, info.CapabilityFlags)
	require.Contains(t, info.Capabilities, "SupportsAuthPlugins")
	require.Equal(t, "handshake", info.Debug.PacketType)
	require.Equal(t, info.Version, info.Debug.Version)
	require.Contains(t, info.Raw, `"packetType":"handshake"`)
	require.Contains(t, info.Raw, `"version":"8.0.28"`)

	ok, err := client.IsMySQL(ctx, host, port)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestFingerprintMySQLClientErrorGreeting(t *testing.T) {
	t.Parallel()

	msg := "Host '1.2.3.4' is not allowed to connect to this MySQL server"
	payload := []byte{0xff, 0x6a, 0x04}
	payload = append(payload, []byte(msg)...)
	pkt := buildPacket(t, payload)

	ctx, _ := initMySQLExec(t)
	host, port := startGreetingServer(t, pkt, nil)

	client := &MySQLClient{}
	info, err := client.FingerprintMySQL(ctx, host, port)
	require.NoError(t, err)
	require.Empty(t, info.Version)
	require.Equal(t, "error", info.Debug.PacketType)
	require.Equal(t, 0x046a, info.Debug.ErrorCode)
	require.Equal(t, msg, info.Debug.ErrorMessage)
	require.Contains(t, info.Raw, `"packetType":"error"`)

	ok, err := client.IsMySQL(ctx, host, port)
	require.NoError(t, err)
	require.True(t, ok, "error greetings are still MySQL, same as fingerprintx")
}

func TestFingerprintMySQLAndIsMySQLShareOneDial(t *testing.T) {
	t.Parallel()

	var dials atomic.Int32
	ctx, _ := initMySQLExec(t)
	host, port := startGreetingServer(t, testHandshakePacket(t), &dials)

	client := &MySQLClient{}
	ok, err := client.IsMySQL(ctx, host, port)
	require.NoError(t, err)
	require.True(t, ok)

	info, err := client.FingerprintMySQL(ctx, host, port)
	require.NoError(t, err)
	require.Equal(t, "8.0.28", info.Version)
	require.Equal(t, int32(1), dials.Load(), "memoized probe must dial once")
}

func TestFingerprintMySQLRejectsNonMySQL(t *testing.T) {
	t.Parallel()

	ctx, _ := initMySQLExec(t)
	host, port := startGreetingServer(t, []byte("SSH-2.0-OpenSSH_8.0\r\n"), nil)

	client := &MySQLClient{}
	_, err := client.FingerprintMySQL(ctx, host, port)
	require.Error(t, err)

	ok, err := client.IsMySQL(ctx, host, port)
	require.Error(t, err)
	require.False(t, ok)
}

func TestFingerprintMySQLNativePasswordVersion(t *testing.T) {
	t.Parallel()

	ctx, _ := initMySQLExec(t)
	host, port := startGreetingServer(t, testNativePasswordHandshake(t), nil)

	info, err := (&MySQLClient{}).FingerprintMySQL(ctx, host, port)
	require.NoError(t, err)
	require.Equal(t, "5.7.44", info.Version)
	require.Equal(t, "mysql_native_password", info.AuthPluginName)
	require.NotEmpty(t, info.Version, "version must always be detected on valid handshake")
}

func TestFingerprintMySQLDeniedByNetworkPolicy(t *testing.T) {
	t.Parallel()

	executionID := "mysql-deny-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck

	_, err := (&MySQLClient{}).FingerprintMySQL(ctx, "127.0.0.1", 3306)
	require.Error(t, err)
	require.Contains(t, err.Error(), "127.0.0.1")
}

func TestFingerprintMySQLVersionNeverEmptyOnHandshakeFixtures(t *testing.T) {
	t.Parallel()

	fixtures := []struct {
		name    string
		packet  []byte
		version string
	}{
		{"8.0", testHandshakePacket(t), "8.0.28"},
		{"5.7", testNativePasswordHandshake(t), "5.7.44"},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			ctx, _ := initMySQLExec(t)
			host, port := startGreetingServer(t, fx.packet, nil)
			info, err := (&MySQLClient{}).FingerprintMySQL(ctx, host, port)
			require.NoError(t, err)
			require.Equal(t, fx.version, info.Version)
			require.NotEmpty(t, info.Version)
			require.Equal(t, fx.version, info.Debug.Version)
		})
	}
}
