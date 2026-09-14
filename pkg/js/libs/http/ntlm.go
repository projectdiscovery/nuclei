package http

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

type (
	// NTLMInfo holds fields decoded from an NTLM Type-2 challenge
	// (Burp ntlm-challenge-decoder / nmap-style AV pairs).
	// @example
	// ```javascript
	// const http = require('nuclei/http');
	// const resp = http.Get('https://exchange.acme.local/ews/');
	// const info = http.DecodeNTLM(resp.GetHeader('WWW-Authenticate'));
	// log(info.DNSComputerName + ' ' + info.DNSDomainName);
	// ```
	NTLMInfo struct {
		MessageType         int
		TargetName          string
		NetBIOSDomainName   string
		NetBIOSComputerName string
		DNSDomainName       string
		DNSComputerName     string
		DNSTreeName         string
		ProductVersion      string
		Timestamp           uint64
		UnixTimestamp       int64
	}
)

// DecodeNTLM decodes an NTLM SSP blob from a WWW-Authenticate / Authorization
// header value or raw base64. Accepts prefixes "NTLM " and "Negotiate ".
// Only Type-2 (challenge) messages populate TargetInfo fields.
// @example
// ```javascript
// const http = require('nuclei/http');
// const info = http.DecodeNTLM('NTLM TlRMTVNTUAACAAAA...');
// ```
func DecodeNTLM(blob string) (*NTLMInfo, error) {
	raw, err := decodeNTLMBlob(blob)
	if err != nil {
		return nil, err
	}
	return parseNTLMMessage(raw)
}

// NegotiateNTLM returns a base64 Type-1 NTLM negotiate message suitable for
// an Authorization header (without the "NTLM " prefix).
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// client.SetHeader('Authorization', 'NTLM ' + http.NegotiateNTLM());
// const resp = client.Get('https://exchange.acme.local/ews/');
// ```
func NegotiateNTLM() string {
	return base64.StdEncoding.EncodeToString(createNegotiateMessage())
}

func decodeNTLMBlob(blob string) ([]byte, error) {
	s := strings.TrimSpace(blob)
	if s == "" {
		return nil, fmt.Errorf("ntlm: empty blob")
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "ntlm "):
		s = strings.TrimSpace(s[5:])
	case strings.HasPrefix(lower, "negotiate "):
		s = strings.TrimSpace(s[10:])
	}
	// Some servers return "Negotiate <spnego>" - still try base64 of remainder.
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("ntlm: base64 decode: %w", err)
		}
	}
	return raw, nil
}

func parseNTLMMessage(data []byte) (*NTLMInfo, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("ntlm: message too short")
	}
	if !bytes.HasPrefix(data, []byte("NTLMSSP\x00")) {
		return nil, fmt.Errorf("ntlm: missing NTLMSSP signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	info := &NTLMInfo{MessageType: int(msgType)}
	if msgType != 2 {
		// Type 1/3: return type only; TargetInfo is Type-2 specific.
		return info, nil
	}
	if len(data) < 48 {
		return nil, fmt.Errorf("ntlm: challenge too short")
	}

	targetNameLen := binary.LittleEndian.Uint16(data[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(data[16:20])
	if targetNameLen > 0 && int(targetNameOffset)+int(targetNameLen) <= len(data) {
		info.TargetName = decodeUTF16LE(data[targetNameOffset : targetNameOffset+uint32(targetNameLen)])
	}

	negotiateFlags := binary.LittleEndian.Uint32(data[20:24])

	targetInfoLen := binary.LittleEndian.Uint16(data[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(data[44:48])
	start := uint64(targetInfoOffset)
	end := start + uint64(targetInfoLen)
	if targetInfoLen > 0 && end <= uint64(len(data)) {
		parseAVPairs(data[int(start):int(end)], info)
	}

	// VERSION is only present when NTLMSSP_NEGOTIATE_VERSION is set (MS-NLMP).
	const ntlmsspNegotiateVersion = 0x02000000
	if negotiateFlags&ntlmsspNegotiateVersion != 0 && len(data) >= 56 && info.ProductVersion == "" {
		major := data[48]
		minor := data[49]
		build := binary.LittleEndian.Uint16(data[50:52])
		info.ProductVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}

	if info.Timestamp > 0 {
		info.UnixTimestamp = int64(info.Timestamp/10000000) - 11644473600
	}
	return info, nil
}

func parseAVPairs(data []byte, info *NTLMInfo) {
	for i := 0; i+4 <= len(data); {
		avID := binary.LittleEndian.Uint16(data[i : i+2])
		avLen := binary.LittleEndian.Uint16(data[i+2 : i+4])
		i += 4
		if avID == 0 { // MsvAvEOL
			break
		}
		if i+int(avLen) > len(data) {
			break
		}
		val := data[i : i+int(avLen)]
		i += int(avLen)
		switch avID {
		case 1:
			info.NetBIOSComputerName = decodeUTF16LE(val)
		case 2:
			info.NetBIOSDomainName = decodeUTF16LE(val)
		case 3:
			info.DNSComputerName = decodeUTF16LE(val)
		case 4:
			info.DNSDomainName = decodeUTF16LE(val)
		case 5:
			info.DNSTreeName = decodeUTF16LE(val)
		case 7: // MsvAvTimestamp
			if len(val) >= 8 {
				info.Timestamp = binary.LittleEndian.Uint64(val)
			}
		case 8: // MsvAvSingleHost — binary structure, not UTF-16 text
		case 9: // MsvAvTargetName (SPN)
			if info.TargetName == "" {
				info.TargetName = decodeUTF16LE(val)
			}
		}
	}
}

func decodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func createNegotiateMessage() []byte {
	var buf bytes.Buffer
	buf.WriteString("NTLMSSP")
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	flags := uint32(0x00000001 | // UNICODE
		0x00000002 | // OEM
		0x00000004 | // Request Target
		0x00000200 | // NTLM
		0x00008000 | // Always Sign
		0x00080000 | // NTLM2 Key
		0x20000000 | // 128
		0x80000000) // 56
	_ = binary.Write(&buf, binary.LittleEndian, flags)
	// empty domain / workstation buffers (length, maxlen, offset)
	zeros := make([]byte, 16)
	buf.Write(zeros)
	return buf.Bytes()
}
