package mssql

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// errNotMssql marks a completed probe whose response is not a valid MSSQL
// pre-login reply. IsMssql maps this to (false, nil); FingerprintMssql still
// surfaces it as an error.
var errNotMssql = errors.New("not a mssql service")

const (
	mssqlFingerprintTimeout = 5 * time.Second

	tdsTypeTabularResult = 0x04
	tdsStatusEOM         = 0x01
	tdsTerminator        = 0xff

	plTokenVersion    = 0x00
	plTokenEncryption = 0x01
	plTokenInstOpt    = 0x02
	plTokenThreadID   = 0x03
	plTokenMars       = 0x04
	plTokenTraceID    = 0x05

	encryptOff    = 0x00
	encryptOn     = 0x01
	encryptNotSup = 0x02
	encryptReq    = 0x03
)

// preLoginRequest is a standard TDS pre-login packet (same shape fingerprintx uses).
var preLoginRequest = []byte{
	0x12, 0x01, 0x00, 0x58, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x1f, 0x00, 0x06,
	0x01, 0x00, 0x25, 0x00, 0x01,
	0x02, 0x00, 0x26, 0x00, 0x01,
	0x03, 0x00, 0x27, 0x00, 0x04,
	0x04, 0x00, 0x2b, 0x00, 0x01,
	0x05, 0x00, 0x2c, 0x00, 0x24,
	0xff,
	0x11, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0xf9, 0xb8, 0xcb,
	0x5c, 0x94, 0x6b, 0x89, 0x1f, 0xd9, 0xaa, 0x3c,
	0x13, 0x4b, 0xd0, 0x7b, 0x88, 0x03, 0x5c, 0x32,
	0x21, 0x24, 0xa2, 0x81, 0x86, 0x37, 0xcf, 0x62,
	0x39, 0x4a, 0x46, 0x2c, 0xc6, 0x00, 0x00, 0x00,
	0x00,
}

type (
	// MSSQLInfo contains TDS pre-login fingerprint data.
	// @example
	// ```javascript
	// const mssql = require('nuclei/mssql');
	// const info = mssql.FingerprintMssql('acme.com', 1433);
	// ```
	MSSQLInfo struct {
		Host            string `json:"host,omitempty"`
		IP              string `json:"ip,omitempty"`
		Port            int    `json:"port"`
		Protocol        string `json:"protocol"`
		TLS             bool   `json:"tls"`
		Transport       string `json:"transport"`
		Version         string `json:"version,omitempty"`
		MajorVersion    int    `json:"majorVersion,omitempty"`
		MinorVersion    int    `json:"minorVersion,omitempty"`
		BuildNumber     int    `json:"buildNumber,omitempty"`
		Encryption      int    `json:"encryption"`
		EncryptionMode  string `json:"encryptionMode,omitempty"`
		Mars            bool   `json:"mars"`
		InstanceMatches bool   `json:"instanceMatches"`
		Raw             string `json:"raw,omitempty"`
	}
)

// FingerprintMssql gathers MSSQL pre-login fingerprint data from the target.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const info = mssql.FingerprintMssql('acme.com', 1433);
// log(to_json(info));
// ```
func (c *MSSQLClient) FingerprintMssql(ctx context.Context, host string, port int) (MSSQLInfo, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedfingerprintMssql(ctx, executionId, host, port)
}

// @memo
func fingerprintMssql(ctx context.Context, executionId string, host string, port int) (MSSQLInfo, error) {
	info := MSSQLInfo{
		Host:      host,
		Port:      port,
		Protocol:  "mssql",
		Transport: "tcp",
	}
	if host == "" || port <= 0 {
		return info, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, host) {
		return info, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return info, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return info, err
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(mssqlFingerprintTimeout))
	if _, err := conn.Write(preLoginRequest); err != nil {
		return info, err
	}

	// Read TDS header first, then remaining payload by Length field.
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return info, err
	}
	packetLen := int(binary.BigEndian.Uint16(header[2:4]))
	if packetLen < 8 {
		return info, fmt.Errorf("%w: invalid TDS packet length %d", errNotMssql, packetLen)
	}
	body := make([]byte, packetLen-8)
	if packetLen > 8 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return info, err
		}
	}
	response := append(header, body...)

	parsed, err := parsePreloginResponse(response)
	if err != nil {
		return info, fmt.Errorf("%w: %v", errNotMssql, err)
	}
	info.Version = parsed.Version
	info.MajorVersion = parsed.MajorVersion
	info.MinorVersion = parsed.MinorVersion
	info.BuildNumber = parsed.BuildNumber
	info.Encryption = parsed.Encryption
	info.EncryptionMode = parsed.EncryptionMode
	info.Mars = parsed.Mars
	info.InstanceMatches = parsed.InstanceMatches
	info.TLS = parsed.Encryption == encryptOn || parsed.Encryption == encryptReq
	info.Raw = hex.EncodeToString(response)
	if ip := net.ParseIP(host); ip != nil {
		info.IP = ip.String()
	}
	return info, nil
}

type preloginData struct {
	Version         string
	MajorVersion    int
	MinorVersion    int
	BuildNumber     int
	Encryption      int
	EncryptionMode  string
	Mars            bool
	InstanceMatches bool
}

func parsePreloginResponse(response []byte) (preloginData, error) {
	var out preloginData
	if len(response) < 8 {
		return out, fmt.Errorf("response too short for TDS header")
	}
	if response[0] != tdsTypeTabularResult {
		return out, fmt.Errorf("unexpected TDS type 0x%02x", response[0])
	}
	if response[1] != tdsStatusEOM {
		return out, fmt.Errorf("unexpected TDS status 0x%02x", response[1])
	}
	packetLength := int(binary.BigEndian.Uint16(response[2:4]))
	if len(response) != packetLength {
		return out, fmt.Errorf("packet length mismatch: header=%d body=%d", packetLength, len(response))
	}

	type optionToken struct {
		token  byte
		offset uint16
		length uint16
		data   []byte
	}

	position := 8
	var tokens []optionToken
	for position < len(response) {
		if response[position] == tdsTerminator {
			break
		}
		if position+5 > len(response) {
			return out, fmt.Errorf("truncated PL option token")
		}
		token := response[position]
		offset := binary.BigEndian.Uint16(response[position+1 : position+3])
		length := binary.BigEndian.Uint16(response[position+3 : position+5])
		var data []byte
		if length > 0 {
			start := int(offset) + 8
			end := start + int(length)
			if start < 8 || end > len(response) {
				return out, fmt.Errorf("invalid PL option data range")
			}
			data = response[start:end]
		}
		tokens = append(tokens, optionToken{token: token, offset: offset, length: length, data: data})
		position += 5
	}
	if position >= len(response) || response[position] != tdsTerminator {
		return out, fmt.Errorf("missing PL option terminator")
	}
	if len(tokens) == 0 {
		return out, fmt.Errorf("no PL option tokens")
	}
	if tokens[0].token != plTokenVersion {
		return out, fmt.Errorf("first PL option must be VERSION")
	}
	if len(tokens[0].data) < 4 {
		return out, fmt.Errorf("VERSION option too short")
	}

	out.MajorVersion = int(tokens[0].data[0])
	out.MinorVersion = int(tokens[0].data[1])
	out.BuildNumber = int(tokens[0].data[2])<<8 | int(tokens[0].data[3])
	out.Version = fmt.Sprintf("%d.%d.%d", out.MajorVersion, out.MinorVersion, out.BuildNumber)

	for _, tok := range tokens[1:] {
		switch tok.token {
		case plTokenEncryption:
			if len(tok.data) > 0 {
				out.Encryption = int(tok.data[0])
				out.EncryptionMode = encryptionModeName(tok.data[0])
			}
		case plTokenInstOpt:
			// 0x00 means the instance name matched (or none was requested).
			out.InstanceMatches = len(tok.data) == 0 || tok.data[0] == 0
		case plTokenMars:
			out.Mars = len(tok.data) > 0 && tok.data[0] == 1
		case plTokenThreadID, plTokenTraceID:
			// ignored for fingerprinting
		}
	}
	if out.EncryptionMode == "" {
		out.EncryptionMode = encryptionModeName(byte(out.Encryption))
	}
	return out, nil
}

func encryptionModeName(v byte) string {
	switch v {
	case encryptOff:
		return "ENCRYPT_OFF"
	case encryptOn:
		return "ENCRYPT_ON"
	case encryptNotSup:
		return "ENCRYPT_NOT_SUP"
	case encryptReq:
		return "ENCRYPT_REQ"
	default:
		return fmt.Sprintf("UNKNOWN_0x%02x", v)
	}
}
