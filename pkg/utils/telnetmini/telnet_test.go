package telnetmini

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStripTelnetCommands(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"plain text", []byte("Login: "), "Login: "},
		{"option negotiation", []byte{IAC, DO, 0x18, IAC, WILL, 0x01, 'h', 'i'}, "hi"},
		{"subnegotiation", []byte{IAC, SB, 0x18, 0x01, IAC, SE, 'o', 'k'}, "ok"},
		{"escaped IAC", []byte{'a', IAC, IAC, 'b'}, "a\xffb"},
		{"two-byte command", []byte{IAC, 241, 'x'}, "x"},
		{"non-ASCII text", []byte("caf\xc3\xa9"), "café"},
		{"truncated command", []byte{'a', IAC}, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, string(stripTelnetCommands(tt.in)))
		})
	}
}

func TestDetectEncryptionBannerExcludesNegotiation(t *testing.T) {
	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
	}()

	go func() {
		defer func() {
			_ = server.Close()
		}()
		// Consume the IAC DO/WILL ENCRYPT probe.
		probe := make([]byte, 6)
		if _, err := io.ReadFull(server, probe); err != nil {
			return
		}
		_ = server.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = server.Write([]byte{IAC, DO, 0x18, IAC, WILL, 0x01, IAC, SB, 0x18, 0x01, IAC, SE})
		_, _ = server.Write([]byte("Ubuntu 26.04 caf\xc3\xa9\r\nlogin: "))
	}()

	info, err := DetectEncryption(client, 2*time.Second)
	require.NoError(t, err)
	require.Equal(t, "Ubuntu 26.04 caf\xc3\xa9\r\nlogin: ", info.Banner)
	require.Contains(t, info.Options, 0x18)
}
