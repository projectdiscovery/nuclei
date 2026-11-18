package ipmi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// The fixtures were captured from OpenIPMI's ipmi_sim with an enabled user
// with an empty name and password, ADMIN/ADMIN and root/calvin.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	require.NoError(t, err)
	return data
}

func TestParseAuthCapabilities(t *testing.T) {
	caps, err := parseAuthCapabilities(mustHex(t, "0197050300000000"))
	require.NoError(t, err)
	require.Equal(t, &AuthCapabilities{
		IPMI20:           true,
		AuthTypes:        []string{"none", "md2", "md5", "straight"},
		AnonymousLogin:   true,
		NonNullUsernames: true,
		PerMessageAuth:   true,
		UserLevelAuth:    true,
	}, caps)

	_, err = parseAuthCapabilities(mustHex(t, "0197"))
	require.Error(t, err)
}

func TestParseCipherSuites(t *testing.T) {
	records := mustHex(t, "c000004080c001014080c002014180c003014181c004014182c005014183c006024080c007024280c008024281c009024282c00a024283c00b024380c00c024381c00d024382c00e024383")
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, parseCipherSuites(records))

	// an oem record carries a 3 byte IANA before its algorithms
	require.Equal(t, []int{1, 7}, parseCipherSuites(mustHex(t, "c0010140c107d70200014080")))
}

func TestRAKPPasswordChecksAreOffline(t *testing.T) {
	// hashcat -m 7300 cracks this hash to calvin as well
	hash := &RAKPHash{
		Username: "root",
		Salt:     "988200cd0402000069b30c7a5e3deb30504c5b76f7b1840d5e36439998d9e0f59ae49b09119a10b2a123456789abcdefa123456789abcdef1404726f6f74",
		HMAC:     "23c711e5c7a737c3c0beb9f4680ef31fa6aad398",
	}
	require.True(t, CheckRAKPPassword(hash, "calvin"))
	require.False(t, CheckRAKPPassword(hash, "ADMIN"))
	require.Equal(t, "calvin", FindRAKPPassword(hash, []string{"admin", "root", "calvin"}))
	require.Empty(t, FindRAKPPassword(hash, []string{"admin"}))
	require.False(t, CheckRAKPPassword(nil, "calvin"))
	require.False(t, CheckRAKPPassword(&RAKPHash{Salt: "zz", HMAC: "00"}, "calvin"))
}

func TestRequestsHonourNetworkPolicy(t *testing.T) {
	execID := "ipmi-deny"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID, ExcludeTargets: []string{"203.0.113.50"}}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	_, err := GetRAKPHash(ctx, "203.0.113.50", 623, "ADMIN")
	require.ErrorContains(t, err, "denied")
	require.NotErrorIs(t, err, errNoResponse, "denied before sending, not timed out")
	_, err = Ping(ctx, "203.0.113.50", 623)
	require.ErrorContains(t, err, "denied")
}

func TestPayloadEncryptionRoundTrips(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	for size := range 40 {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		sealed, err := encryptPayload(key, payload)
		require.NoError(t, err)
		require.Zero(t, len(sealed)%16, "iv and padded blocks")
		opened, err := decryptPayload(key, sealed)
		require.NoError(t, err)
		require.Equal(t, payload, opened)
	}
	_, err := decryptPayload(key, []byte{1, 2, 3})
	require.Error(t, err)
}

func TestSignAlignsTheIntegrityPad(t *testing.T) {
	e := &established{algorithms: cipherSuites[3], keys: &keys{integrity: make([]byte, 20)}}
	for size := range 8 {
		packet := append(rmcpHeader(rmcpClassIPMI), make([]byte, 12+size)...)
		signed := e.sign(packet)
		// everything from the auth type through the next header is a
		// multiple of 4, then 12 bytes of HMAC-SHA1-96
		require.Zero(t, (len(signed)-12-4)%4)
		require.Equal(t, byte(0x07), signed[len(signed)-13])
	}
}

func TestLoginRejectsUnsupportedCipherSuites(t *testing.T) {
	_, err := (&Client{}).Login(context.Background(), "127.0.0.1", 623, "ADMIN", "ADMIN", 17)
	require.ErrorContains(t, err, "unsupported cipher suite 17")
	_, err = (&Client{}).Command(0x06, 0x01, nil)
	require.ErrorContains(t, err, "not logged in")
}

// capturedHandshake is a cipher suite 3 session setup with ipmi_sim for
// ADMIN/ADMIN, up to and including RAKP message 4.
func capturedHandshake(t *testing.T) (*handshake, []byte) {
	return &handshake{
		algorithms:       cipherSuites[3],
		consoleSessionID: mustHex(t, "244a5ac8"),
		bmcSessionID:     mustHex(t, "04170000"),
		consoleRandom:    mustHex(t, "de862025bb0c5ee6c30a58d383d44cb5"),
		bmcRandom:        mustHex(t, "b56fef2ee0fcab6664a019a4c88df4f6"),
		bmcGUID:          mustHex(t, "a123456789abcdefa123456789abcdef"),
		role:             0x14,
		username:         "ADMIN",
		bmcMAC:           mustHex(t, "7fac6f776553c58df508b9ff656b5eacb6c2def9"),
	}, mustHex(t, "00000000244a5ac8231219c5fc212cdd58c09424")
}

func TestBMCProofsMatchOnlyTheRealPassword(t *testing.T) {
	h, rakp4 := capturedHandshake(t)
	sik := func(password string) []byte {
		return hmacOf(sha1.New, []byte(password), h.consoleRandom, h.bmcRandom, []byte{h.role, byte(len(h.username))}, []byte(h.username))
	}

	require.Equal(t, h.bmcMAC, hmacOf(sha1.New, []byte("ADMIN"), h.rakp2Salt()), "rakp 2 code")
	require.NotEqual(t, h.bmcMAC, hmacOf(sha1.New, []byte("wrong"), h.rakp2Salt()))

	require.True(t, rakp4Valid(sha1.New, sik("ADMIN"), h, rakp4))
	require.False(t, rakp4Valid(sha1.New, sik("wrong"), h, rakp4))
	tampered := bytes.Clone(rakp4)
	tampered[len(tampered)-1] ^= 0xff
	require.False(t, rakp4Valid(sha1.New, sik("ADMIN"), h, tampered), "a forged success must not pass")
	require.False(t, rakp4Valid(sha1.New, sik("ADMIN"), h, rakp4[:10]))
}

func TestShortCommandReplyIsRejectedNotPanicked(t *testing.T) {
	execID := "ipmi-short"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	// a reply that ends at the completion code, without the checksum
	bmc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = bmc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := bmc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := bytes.Clone(buf[:21])
			reply[19] = buf[n-2] // echo the command
			reply[20] = 0x00
			_, _ = bmc.WriteTo(reply, addr)
		}
	}()

	port := bmc.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = GetSystemGUID(ctx, "127.0.0.1", port)
	require.ErrorIs(t, err, errNoResponse)
}
