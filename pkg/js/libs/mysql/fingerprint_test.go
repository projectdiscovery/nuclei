package mysql

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	fxmysql "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
	"github.com/stretchr/testify/require"
)

func buildPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	require.LessOrEqual(t, len(payload), 0xffffff)
	header := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		0x00,
	}
	return append(header, payload...)
}

// Golden handshake derived from the MySQL initial-handshake layout documented in
// fingerprintx (version 8.0.28, protocol 10, caching_sha2_password).
func testHandshakePacket(t *testing.T) []byte {
	t.Helper()
	payload := []byte{0x0a}
	payload = append(payload, []byte("8.0.28")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x0b, 0x00, 0x00, 0x00)                         // thread id 11
	payload = append(payload, 0x15, 0x05, 0x6c, 0x51, 0x28, 0x32, 0x48, 0x15) // salt part1
	payload = append(payload, 0x00)                                           // filler
	payload = append(payload, 0xff, 0xff)                                     // cap lower
	payload = append(payload, 0xff)                                           // charset
	payload = append(payload, 0x02, 0x00)                                     // status autocommit
	payload = append(payload, 0xff, 0xdf)                                     // cap upper (includes plugin auth)
	payload = append(payload, 0x15)                                           // auth plugin data len = 21
	payload = append(payload, make([]byte, 10)...)                            // reserved
	payload = append(payload, 0x26, 0x68, 0x15, 0x1e, 0x2e, 0x7f, 0x69, 0x38, 0x52, 0x6b, 0x6c, 0x5c, 0x00)
	payload = append(payload, []byte("caching_sha2_password")...)
	payload = append(payload, 0x00)
	return buildPacket(t, payload)
}

func testNativePasswordHandshake(t *testing.T) []byte {
	t.Helper()
	// MySQL 5.7-style greeting with mysql_native_password.
	payload := []byte{0x0a}
	payload = append(payload, []byte("5.7.44")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x2a, 0x00, 0x00, 0x00) // thread id 42
	payload = append(payload, []byte("12345678")...)  // salt part1
	payload = append(payload, 0x00)
	payload = append(payload, 0xff, 0xf7) // cap lower
	payload = append(payload, 0x08)       // charset
	payload = append(payload, 0x02, 0x00) // autocommit
	payload = append(payload, 0x08, 0x00) // cap upper with CLIENT_PLUGIN_AUTH (bit 19)
	payload = append(payload, 0x15)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, []byte("abcdefghijkl")...)
	payload = append(payload, 0x00)
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0x00)
	return buildPacket(t, payload)
}

func TestParseMySQLHandshakePacket(t *testing.T) {
	t.Parallel()

	info, err := parseMySQLGreeting(testHandshakePacket(t))
	require.NoError(t, err)
	require.Equal(t, "handshake", info.PacketType)
	require.Equal(t, 10, info.ProtocolVersion)
	require.Equal(t, "8.0.28", info.Version)
	require.Equal(t, uint32(11), info.ThreadID)
	require.Equal(t, uint8(0xff), info.CharacterSet)
	require.Equal(t, uint16(0x0002), info.StatusFlags)
	require.Equal(t, []string{"Autocommit"}, info.Status)
	require.Equal(t, "caching_sha2_password", info.AuthPluginName)
	require.Equal(t, 21, info.AuthPluginDataLen)
	require.Equal(t, uint32(0xdfffffff), info.CapabilityFlags)
	require.Contains(t, info.Capabilities, "SupportsAuthPlugins")
	require.Contains(t, info.Capabilities, "SwitchToSSLAfterHandshake")
	require.Contains(t, info.Capabilities, "SupportsTransactions")
	require.NotEmpty(t, info.Salt)

	saltRaw, err := hex.DecodeString("15056c51283248152668151e2e7f6938526b6c5c")
	require.NoError(t, err)
	require.Equal(t, formatSalt(saltRaw), info.Salt)
}

func TestParseMySQLNativePasswordHandshake(t *testing.T) {
	t.Parallel()

	info, err := parseMySQLGreeting(testNativePasswordHandshake(t))
	require.NoError(t, err)
	require.Equal(t, "handshake", info.PacketType)
	require.Equal(t, "5.7.44", info.Version)
	require.Equal(t, uint32(42), info.ThreadID)
	require.Equal(t, "mysql_native_password", info.AuthPluginName)
	require.Contains(t, info.Capabilities, "SupportsAuthPlugins")
	require.Contains(t, info.Salt, "12345678")
}

func TestParseMySQLHandshakeWithoutPluginAuth(t *testing.T) {
	t.Parallel()

	payload := []byte{0x0a}
	payload = append(payload, []byte("5.5.5-MariaDB")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)
	payload = append(payload, []byte("abcdefgh")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0xff, 0xf7) // no plugin-auth in upper caps
	payload = append(payload, 0x08)
	payload = append(payload, 0x02, 0x00)
	payload = append(payload, 0x00, 0x00) // cap upper without plugin auth
	payload = append(payload, 0x00)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, []byte("ijklmnopabcd")...)
	payload = append(payload, 0x00)

	info, err := parseMySQLGreeting(buildPacket(t, payload))
	require.NoError(t, err)
	require.Equal(t, "5.5.5-MariaDB", info.Version)
	require.Empty(t, info.AuthPluginName)
	require.NotContains(t, info.Capabilities, "SupportsAuthPlugins")
}

func TestParseMySQLErrorPacket(t *testing.T) {
	t.Parallel()

	msg := "Host '1.2.3.4' is not allowed to connect to this MySQL server"
	payload := []byte{0xff, 0x6a, 0x04}
	payload = append(payload, []byte(msg)...)

	info, err := parseMySQLGreeting(buildPacket(t, payload))
	require.NoError(t, err)
	require.Equal(t, "error", info.PacketType)
	require.Equal(t, 0x046a, info.ErrorCode)
	require.Equal(t, msg, info.ErrorMessage)
	require.Empty(t, info.Version)
	require.Zero(t, info.ThreadID)
}

func TestParseMySQLErrorPacketWithSQLState(t *testing.T) {
	t.Parallel()

	payload := []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
	payload = append(payload, []byte("Access denied for user")...)

	info, err := parseMySQLGreeting(buildPacket(t, payload))
	require.NoError(t, err)
	require.Equal(t, "error", info.PacketType)
	require.Equal(t, 0x0415, info.ErrorCode)
	require.Equal(t, "Access denied for user", info.ErrorMessage)
}

func TestParseMySQLHandshakeRejectsGarbage(t *testing.T) {
	t.Parallel()

	_, err := parseMySQLGreeting([]byte{0x01, 0x00, 0x00, 0x00, 0x09})
	require.Error(t, err)

	_, err = parseMySQLGreeting([]byte{0x00})
	require.Error(t, err)

	_, err = parseMySQLGreeting(buildPacket(t, []byte{0x0a, 'x'})) // truncated after version byte
	require.Error(t, err)
}

func TestParseMySQLHandshakeRejectsBadFiller(t *testing.T) {
	t.Parallel()

	payload := []byte{0x0a, '8', '.', '0', 0x00}
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)
	payload = append(payload, []byte("12345678")...)
	payload = append(payload, 0x01) // bad filler
	payload = append(payload, make([]byte, 20)...)

	_, err := parseMySQLGreeting(buildPacket(t, payload))
	require.Error(t, err)
	require.Contains(t, err.Error(), "filler")
}

func TestFormatSaltEscapesBinary(t *testing.T) {
	t.Parallel()

	raw, err := hex.DecodeString("15056c51")
	require.NoError(t, err)
	got := formatSalt(raw)
	require.Equal(t, `\x15\x05lQ`, got)
}

func TestDecodeCapabilityAndStatusFlags(t *testing.T) {
	t.Parallel()

	caps := decodeCapabilityFlags(clientSSL | clientPluginAuth | clientTransactions)
	require.Equal(t, []string{"SwitchToSSLAfterHandshake", "SupportsTransactions", "SupportsAuthPlugins"}, caps)

	status := decodeStatusFlags(serverStatusAutocommit | serverStatusInTrans)
	require.Equal(t, []string{"InTransaction", "Autocommit"}, status)

	require.Empty(t, decodeCapabilityFlags(0))
	require.Empty(t, decodeStatusFlags(0))
}

func TestHandshakeToJSON(t *testing.T) {
	t.Parallel()

	info, err := parseMySQLGreeting(testHandshakePacket(t))
	require.NoError(t, err)
	raw := handshakeToJSON(info)
	require.Contains(t, raw, `"packetType":"handshake"`)
	require.Contains(t, raw, `"version":"8.0.28"`)
	require.Contains(t, raw, `"authPluginName":"caching_sha2_password"`)
}

func TestFingerprintConnReadsGreetingOnce(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	packet := testHandshakePacket(t)
	errCh := make(chan error, 1)
	go func() {
		_, err := server.Write(packet)
		errCh <- err
		_ = server.Close()
	}()

	info, err := fingerprintConn(client, time.Second)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	require.Equal(t, "8.0.28", info.Version)
	require.Equal(t, "caching_sha2_password", info.AuthPluginName)
}

func TestRecvMySQLPacketRejectsHugeLength(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go func() {
		// 3-byte length = 0x01000000 (> 16MiB cap) + seq 0
		_, _ = server.Write([]byte{0x00, 0x00, 0x00, 0x01})
		_ = server.Close()
	}()

	_, err := recvMySQLPacket(client, time.Second)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid mysql packet length")
}

func TestCapabilityFlagConstantsMatchWire(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, clientPluginAuth|clientSSL)
	require.Equal(t, byte(0x00), buf[0])
	require.Equal(t, byte(0x08), buf[1]) // SSL in lower
	require.Equal(t, byte(0x08), buf[2]) // plugin auth in upper (bit 19 -> byte2 bit3)
	require.Equal(t, byte(0x00), buf[3])
}

func testMariaDBHandshake(t *testing.T) []byte {
	t.Helper()
	payload := []byte{0x0a}
	payload = append(payload, []byte("5.5.5-10.11.8-MariaDB")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)
	payload = append(payload, []byte("abcdefgh")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0xff, 0xf7)
	payload = append(payload, 0x08)
	payload = append(payload, 0x02, 0x00)
	payload = append(payload, 0x00, 0x00)
	payload = append(payload, 0x00)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, []byte("ijklmnopabcd")...)
	payload = append(payload, 0x00)
	return buildPacket(t, payload)
}

func testMinimalHandshake(t *testing.T) []byte {
	t.Helper()
	// Minimal handshake fingerprintx accepts (len>=35) without full salt/plugin tail.
	payload := []byte{0x0a}
	payload = append(payload, []byte("8.0.28")...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x0b, 0x00, 0x00, 0x00)
	payload = append(payload, 0x15, 0x05, 0x6c, 0x51, 0x28, 0x32, 0x48, 0x15)
	payload = append(payload, 0x00) // filler
	for len(payload) < 31 {        // 4+31 == 35 absolute bytes minimum
		payload = append(payload, 0x00)
	}
	return buildPacket(t, payload)
}

// TestFingerprintxHandshakeVersionParity ensures every greeting fingerprintx
// accepts yields the same Version from our parser (no version regressions).
func TestFingerprintxHandshakeVersionParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		pkt             []byte
		wantVersion     string
		wantEnrichment  bool
		wantAuthPlugin  string
	}{
		{"mysql80", testHandshakePacket(t), "8.0.28", true, "caching_sha2_password"},
		{"mysql57", testNativePasswordHandshake(t), "5.7.44", true, "mysql_native_password"},
		{"mariadb", testMariaDBHandshake(t), "5.5.5-10.11.8-MariaDB", true, ""},
		{"minimal", testMinimalHandshake(t), "8.0.28", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fxVersion, fxErr := fxmysql.CheckInitialHandshakePacket(tc.pkt)
			require.NoError(t, fxErr, "fingerprintx must accept fixture")
			require.Equal(t, tc.wantVersion, fxVersion)

			info, err := parseMySQLGreeting(tc.pkt)
			require.NoError(t, err)
			require.Equal(t, "handshake", info.PacketType)
			require.Equal(t, fxVersion, info.Version, "version must match fingerprintx")
			require.NotEmpty(t, info.Version)
			require.Equal(t, 10, info.ProtocolVersion)
			if tc.wantEnrichment {
				require.NotZero(t, info.ThreadID)
				require.NotEmpty(t, info.Salt)
				require.NotZero(t, info.CapabilityFlags)
			}
			if tc.wantAuthPlugin != "" {
				require.Equal(t, tc.wantAuthPlugin, info.AuthPluginName)
			}
		})
	}
}

func TestFingerprintxErrorPacketParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload []byte
		wantMsg string
		wantCode int
	}{
		{
			name: "host_not_allowed",
			payload: append([]byte{0xff, 0x6a, 0x04},
				[]byte("Host '1.2.3.4' is not allowed to connect to this MySQL server")...),
			wantMsg:  "Host '1.2.3.4' is not allowed to connect to this MySQL server",
			wantCode: 0x046a,
		},
		{
			name: "access_denied_plain",
			payload: append([]byte{0xff, 0x15, 0x04},
				[]byte("Access denied for user 'root'@'localhost'")...),
			wantMsg:  "Access denied for user 'root'@'localhost'",
			wantCode: 0x0415,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pkt := buildPacket(t, tc.payload)

			fxMsg, fxCode, fxErr := fxmysql.CheckErrorMessagePacket(pkt)
			require.NoError(t, fxErr)
			require.Equal(t, tc.wantMsg, fxMsg)
			require.Equal(t, tc.wantCode, fxCode)

			info, err := parseMySQLGreeting(pkt)
			require.NoError(t, err)
			require.Equal(t, "error", info.PacketType)
			require.Equal(t, fxCode, info.ErrorCode)
			require.Equal(t, fxMsg, info.ErrorMessage)
			require.Empty(t, info.Version)
		})
	}
}

// TestFingerprintxRejectParity: packets fingerprintx rejects as both handshake
// and error must also fail our parser (no false MySQL positives on garbage).
func TestFingerprintxRejectParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{0x01, 0x00, 0x00, 0x00, 0x0a}},
		{"ssh_banner", []byte("SSH-2.0-OpenSSH\r\n")},
		{"http", []byte("HTTP/1.1 200 OK\r\n\r\n")},
		{"wrong_protocol", buildPacket(t, append([]byte{0x09}, make([]byte, 40)...))},
		{"non_ascii_version", func() []byte {
			payload := []byte{0x0a, 0x80, 0x00} // non-printable in version
			payload = append(payload, make([]byte, 40)...)
			return buildPacket(t, payload)
		}()},
		{"bad_filler", func() []byte {
			payload := []byte{0x0a, '8', '.', '0', 0x00}
			payload = append(payload, 0x01, 0x00, 0x00, 0x00)
			payload = append(payload, []byte("12345678")...)
			payload = append(payload, 0x01) // bad filler
			payload = append(payload, make([]byte, 20)...)
			return buildPacket(t, payload)
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, hsErr := fxmysql.CheckInitialHandshakePacket(tc.pkt)
			_, _, errErr := fxmysql.CheckErrorMessagePacket(tc.pkt)
			require.Error(t, hsErr)
			require.Error(t, errErr)

			_, err := parseMySQLGreeting(tc.pkt)
			require.Error(t, err, "must reject packets fingerprintx rejects")
		})
	}
}

func TestVersionSurvivesTruncatedEnrichment(t *testing.T) {
	t.Parallel()

	pkt := testMinimalHandshake(t)
	require.GreaterOrEqual(t, len(pkt), 35)

	fxVersion, fxErr := fxmysql.CheckInitialHandshakePacket(pkt)
	require.NoError(t, fxErr)
	require.Equal(t, "8.0.28", fxVersion)

	info, err := parseMySQLGreeting(pkt)
	require.NoError(t, err)
	require.Equal(t, "8.0.28", info.Version)
	require.Equal(t, "handshake", info.PacketType)
	require.Equal(t, uint32(11), info.ThreadID)
}

func TestVersionAlwaysSetOnValidHandshake(t *testing.T) {
	t.Parallel()

	for _, pkt := range [][]byte{
		testHandshakePacket(t),
		testNativePasswordHandshake(t),
		testMariaDBHandshake(t),
		testMinimalHandshake(t),
	} {
		info, err := parseMySQLGreeting(pkt)
		require.NoError(t, err)
		require.NotEmpty(t, info.Version)
		require.Equal(t, 10, info.ProtocolVersion)
	}
}

func TestFingerprintConnErrorGreeting(t *testing.T) {
	t.Parallel()

	msg := "Host '9.9.9.9' is not allowed to connect to this MySQL server"
	payload := append([]byte{0xff, 0x6a, 0x04}, []byte(msg)...)
	packet := buildPacket(t, payload)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := server.Write(packet)
		errCh <- err
		_ = server.Close()
	}()

	info, err := fingerprintConn(client, time.Second)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	require.Equal(t, "error", info.PacketType)
	require.Equal(t, msg, info.ErrorMessage)
	require.Empty(t, info.Version)
}

func TestDebugJSONPreservesFingerprintxFields(t *testing.T) {
	t.Parallel()

	hs, err := parseMySQLGreeting(testHandshakePacket(t))
	require.NoError(t, err)
	raw := handshakeToJSON(hs)
	require.Contains(t, raw, `"packetType":"handshake"`)
	require.Contains(t, raw, `"version":"8.0.28"`)
	// fingerprintx ServiceMySQL always had these keys on error path; present as omitempty on handshake
	require.NotContains(t, raw, `"errorMsg"`)

	msg := "denied"
	payload := append([]byte{0xff, 0x6a, 0x04}, []byte(msg)...)
	errInfo, err := parseMySQLGreeting(buildPacket(t, payload))
	require.NoError(t, err)
	errRaw := handshakeToJSON(errInfo)
	require.Contains(t, errRaw, `"packetType":"error"`)
	require.Contains(t, errRaw, `"errorMsg":"denied"`)
	require.Contains(t, errRaw, `"errorCode":1130`)
}
