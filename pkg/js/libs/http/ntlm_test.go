package http

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

type type2Fields struct {
	computer       string
	domain         string
	dnsComputer    string
	dnsDomain      string
	dnsTree        string
	timestamp      uint64
	targetNameAV   string // MsvAvTargetName (AvId 9)
	omitVersionBit bool   // write VERSION bytes without NTLMSSP_NEGOTIATE_VERSION
}

func buildType2(t *testing.T, f type2Fields) string {
	t.Helper()

	var av []byte
	appendAV := func(id uint16, val []byte) {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
		av = append(av, hdr...)
		av = append(av, val...)
	}
	if f.computer != "" {
		appendAV(1, encodeUTF16LE(f.computer))
	}
	if f.domain != "" {
		appendAV(2, encodeUTF16LE(f.domain))
	}
	if f.dnsComputer != "" {
		appendAV(3, encodeUTF16LE(f.dnsComputer))
	}
	if f.dnsDomain != "" {
		appendAV(4, encodeUTF16LE(f.dnsDomain))
	}
	if f.dnsTree != "" {
		appendAV(5, encodeUTF16LE(f.dnsTree))
	}
	if f.timestamp != 0 {
		ts := make([]byte, 8)
		binary.LittleEndian.PutUint64(ts, f.timestamp)
		appendAV(7, ts)
	}
	if f.targetNameAV != "" {
		appendAV(9, encodeUTF16LE(f.targetNameAV))
	}
	appendAV(0, nil) // EOL

	headerLen := 56
	targetName := encodeUTF16LE(f.computer)
	payloadOff := headerLen
	msg := make([]byte, headerLen+len(targetName)+len(av))
	copy(msg[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(payloadOff))
	copy(msg[payloadOff:], targetName)

	flags := uint32(0)
	if !f.omitVersionBit {
		flags |= 0x02000000 // NTLMSSP_NEGOTIATE_VERSION
	}
	binary.LittleEndian.PutUint32(msg[20:24], flags)

	tiOff := payloadOff + len(targetName)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(av)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(av)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(tiOff))
	copy(msg[tiOff:], av)

	msg[48] = 10
	msg[49] = 0
	binary.LittleEndian.PutUint16(msg[50:52], 19041)

	return "NTLM " + base64.StdEncoding.EncodeToString(msg)
}

func TestDecodeNTLMChallenge(t *testing.T) {
	blob := buildType2(t, type2Fields{computer: "DC01", domain: "ACME"})
	info, err := DecodeNTLM(blob)
	require.NoError(t, err)
	require.Equal(t, 2, info.MessageType)
	require.Equal(t, "DC01", info.NetBIOSComputerName)
	require.Equal(t, "ACME", info.NetBIOSDomainName)
	require.Equal(t, "DC01", info.TargetName)
	require.Equal(t, "10.0.19041", info.ProductVersion)
}

func TestDecodeNTLMVersionRequiresNegotiateFlag(t *testing.T) {
	blob := buildType2(t, type2Fields{computer: "DC01", domain: "ACME", omitVersionBit: true})
	info, err := DecodeNTLM(blob)
	require.NoError(t, err)
	require.Empty(t, info.ProductVersion)
}

func TestDecodeNTLMMsvAvTargetName(t *testing.T) {
	blob := buildType2(t, type2Fields{
		computer:     "DC01",
		domain:       "ACME",
		targetNameAV: "HTTP/exchange.acme.local",
	})
	info, err := DecodeNTLM(blob)
	require.NoError(t, err)
	// TargetName from challenge header wins over MsvAvTargetName when both set.
	require.Equal(t, "DC01", info.TargetName)
}

func TestDecodeNTLMMsvAvTargetNameWhenHeaderEmpty(t *testing.T) {
	blob := buildType2(t, type2Fields{
		domain:       "ACME",
		targetNameAV: "HTTP/exchange.acme.local",
	})
	info, err := DecodeNTLM(blob)
	require.NoError(t, err)
	require.Equal(t, "HTTP/exchange.acme.local", info.TargetName)
}

func TestDecodeNTLMIgnoresMsvAvSingleHostAsTargetName(t *testing.T) {
	// Build a challenge whose only AV payload after domain is AvId 8 (binary), not 9.
	var av []byte
	appendAV := func(id uint16, val []byte) {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
		av = append(av, hdr...)
		av = append(av, val...)
	}
	appendAV(2, encodeUTF16LE("ACME"))
	appendAV(8, []byte{0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Size field shaped garbage
	appendAV(0, nil)

	const headerLen = 56
	msg := make([]byte, headerLen+len(av))
	copy(msg[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint32(msg[20:24], 0x02000000)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(av)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(av)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(headerLen))
	copy(msg[headerLen:], av)
	msg[48], msg[49] = 10, 0
	binary.LittleEndian.PutUint16(msg[50:52], 19041)

	info, err := DecodeNTLM("NTLM " + base64.StdEncoding.EncodeToString(msg))
	require.NoError(t, err)
	require.Empty(t, info.TargetName)
	require.Equal(t, "ACME", info.NetBIOSDomainName)
}

func TestDecodeNTLMChallengeDNSAndTimestamp(t *testing.T) {
	// FILETIME for a known unix second: unix=1700000000 → filetime = (1700000000+11644473600)*10000000
	const unix int64 = 1700000000
	ts := uint64((unix + 11644473600) * 10000000)

	blob := buildType2(t, type2Fields{
		computer:    "DC01",
		domain:      "ACME",
		dnsComputer: "dc01.acme.local",
		dnsDomain:   "acme.local",
		dnsTree:     "acme.local",
		timestamp:   ts,
	})
	info, err := DecodeNTLM(blob)
	require.NoError(t, err)
	require.Equal(t, "dc01.acme.local", info.DNSComputerName)
	require.Equal(t, "acme.local", info.DNSDomainName)
	require.Equal(t, "acme.local", info.DNSTreeName)
	require.Equal(t, ts, info.Timestamp)
	require.Equal(t, unix, info.UnixTimestamp)
}

func TestDecodeNTLMNegotiatePrefix(t *testing.T) {
	inner := buildType2(t, type2Fields{computer: "HOST", domain: "DOM"})
	// strip "NTLM " and wrap as Negotiate
	b64 := inner[len("NTLM "):]
	info, err := DecodeNTLM("Negotiate " + b64)
	require.NoError(t, err)
	require.Equal(t, 2, info.MessageType)
	require.Equal(t, "HOST", info.NetBIOSComputerName)
}

func TestDecodeNTLMRawBase64(t *testing.T) {
	inner := buildType2(t, type2Fields{computer: "RAW", domain: "DOM"})
	info, err := DecodeNTLM(inner[len("NTLM "):])
	require.NoError(t, err)
	require.Equal(t, "RAW", info.NetBIOSComputerName)
}

func TestDecodeNTLMType1Only(t *testing.T) {
	info, err := DecodeNTLM("NTLM " + NegotiateNTLM())
	require.NoError(t, err)
	require.Equal(t, 1, info.MessageType)
}

func TestNegotiateNTLM(t *testing.T) {
	b64 := NegotiateNTLM()
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	require.True(t, len(raw) >= 12)
	require.Equal(t, "NTLMSSP\x00", string(raw[:8]))
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(raw[8:12]))
}

func TestDecodeNTLMInvalid(t *testing.T) {
	_, err := DecodeNTLM("")
	require.Error(t, err)
	_, err = DecodeNTLM("NTLM not-base64!!!")
	require.Error(t, err)
	_, err = DecodeNTLM(base64.StdEncoding.EncodeToString([]byte("short")))
	require.Error(t, err)
	_, err = DecodeNTLM(base64.StdEncoding.EncodeToString(append([]byte("NOTLMSSP\x00"), make([]byte, 20)...)))
	require.Error(t, err)
}

func TestDecodeNTLMIgnoresOversizedTargetInfo(t *testing.T) {
	// Challenge header claims a huge TargetInfo offset that must not panic or
	// be accepted via int truncation on narrower architectures.
	msg := make([]byte, 56)
	copy(msg[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint16(msg[40:42], 4)
	binary.LittleEndian.PutUint32(msg[44:48], 0xffffffff)

	info, err := DecodeNTLM("NTLM " + base64.StdEncoding.EncodeToString(msg))
	require.NoError(t, err)
	require.Equal(t, 2, info.MessageType)
	require.Empty(t, info.NetBIOSDomainName)
	require.Empty(t, info.TargetName)
}

func TestDecodeUTF16LEOddLength(t *testing.T) {
	require.Equal(t, "", decodeUTF16LE(nil))
	// odd length should not panic
	require.NotPanics(t, func() { _ = decodeUTF16LE([]byte{0x41}) })
}
