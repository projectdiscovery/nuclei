package mysql

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	mysqlProtocolVersion10  = 0x0a
	mysqlErrorHeader        = 0xff
	mysqlFingerprintTimeout = 5 * time.Second

	clientLongPassword               = 1 << 0
	clientFoundRows                  = 1 << 1
	clientLongFlag                   = 1 << 2
	clientConnectWithDB              = 1 << 3
	clientNoSchema                   = 1 << 4
	clientCompress                   = 1 << 5
	clientODBC                       = 1 << 6
	clientLocalFiles                 = 1 << 7
	clientIgnoreSpace                = 1 << 8
	clientProtocol41                 = 1 << 9
	clientInteractive                = 1 << 10
	clientSSL                        = 1 << 11
	clientIgnoreSigpipe              = 1 << 12
	clientTransactions               = 1 << 13
	clientReserved                   = 1 << 14
	clientSecureConnection           = 1 << 15
	clientMultiStatements            = 1 << 16
	clientMultiResults               = 1 << 17
	clientPSMultiResults             = 1 << 18
	clientPluginAuth                 = 1 << 19
	clientConnectAttrs               = 1 << 20
	clientPluginAuthLenEncClientData = 1 << 21
	clientCanHandleExpiredPasswords  = 1 << 22
	clientSessionTrack               = 1 << 23
	clientDeprecateEOF               = 1 << 24

	serverStatusInTrans            = 1 << 0
	serverStatusAutocommit         = 1 << 1
	serverMoreResultsExists        = 1 << 3
	serverQueryNoGoodIndexUsed     = 1 << 4
	serverQueryNoIndexUsed         = 1 << 5
	serverStatusCursorExists       = 1 << 6
	serverStatusLastRowSent        = 1 << 7
	serverStatusDBDropped          = 1 << 8
	serverStatusNoBackslashEscapes = 1 << 9
	serverStatusMetadataChanged    = 1 << 10
	serverQueryWasSlow             = 1 << 11
	serverPSOutParams              = 1 << 12
	serverStatusInTransReadonly    = 1 << 13
	serverSessionStateChanged      = 1 << 14
)

var mysqlCapabilityNames = []struct {
	flag uint32
	name string
}{
	{clientLongPassword, "LongPassword"},
	{clientFoundRows, "FoundRows"},
	{clientLongFlag, "LongColumnFlag"},
	{clientConnectWithDB, "ConnectWithDatabase"},
	{clientNoSchema, "DontAllowDatabaseTableColumn"},
	{clientCompress, "SupportsCompression"},
	{clientODBC, "ODBCClient"},
	{clientLocalFiles, "SupportsLoadDataLocal"},
	{clientIgnoreSpace, "IgnoreSpaceBeforeParenthesis"},
	{clientProtocol41, "Speaks41ProtocolNew"},
	{clientInteractive, "InteractiveClient"},
	{clientSSL, "SwitchToSSLAfterHandshake"},
	{clientIgnoreSigpipe, "IgnoreSigpipes"},
	{clientTransactions, "SupportsTransactions"},
	{clientReserved, "Speaks41ProtocolOld"},
	{clientSecureConnection, "Support41Auth"},
	{clientMultiStatements, "SupportsMultipleStatements"},
	{clientMultiResults, "SupportsMultipleResults"},
	{clientPSMultiResults, "SupportsPSMultiResults"},
	{clientPluginAuth, "SupportsAuthPlugins"},
	{clientConnectAttrs, "ConnectAttrs"},
	{clientPluginAuthLenEncClientData, "PluginAuthLenEncClientData"},
	{clientCanHandleExpiredPasswords, "CanHandleExpiredPasswords"},
	{clientSessionTrack, "SessionTrack"},
	{clientDeprecateEOF, "DeprecateEOF"},
}

var mysqlStatusNames = []struct {
	flag uint16
	name string
}{
	{serverStatusInTrans, "InTransaction"},
	{serverStatusAutocommit, "Autocommit"},
	{serverMoreResultsExists, "MoreResultsExists"},
	{serverQueryNoGoodIndexUsed, "NoGoodIndexUsed"},
	{serverQueryNoIndexUsed, "NoIndexUsed"},
	{serverStatusCursorExists, "CursorExists"},
	{serverStatusLastRowSent, "LastRowSent"},
	{serverStatusDBDropped, "DBDropped"},
	{serverStatusNoBackslashEscapes, "NoBackslashEscapes"},
	{serverStatusMetadataChanged, "MetadataChanged"},
	{serverQueryWasSlow, "QueryWasSlow"},
	{serverPSOutParams, "PSOutParams"},
	{serverStatusInTransReadonly, "InTransactionReadonly"},
	{serverSessionStateChanged, "SessionStateChanged"},
}

// HandshakeInfo is the extended MySQL initial-handshake / error fingerprint.
type HandshakeInfo struct {
	PacketType        string   `json:"packetType"`
	ProtocolVersion   int      `json:"protocolVersion,omitempty"`
	Version           string   `json:"version,omitempty"`
	ThreadID          uint32   `json:"threadId,omitempty"`
	CapabilityFlags   uint32   `json:"capabilityFlags,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	CharacterSet      uint8    `json:"characterSet,omitempty"`
	StatusFlags       uint16   `json:"statusFlags,omitempty"`
	Status            []string `json:"status,omitempty"`
	AuthPluginDataLen int      `json:"authPluginDataLen,omitempty"`
	Salt              string   `json:"salt,omitempty"`
	AuthPluginName    string   `json:"authPluginName,omitempty"`
	ErrorMessage      string   `json:"errorMsg,omitempty"`
	ErrorCode         int      `json:"errorCode,omitempty"`
}

// fingerprintConn reads the MySQL greeting once and parses an extended fingerprint.
func fingerprintConn(conn net.Conn, timeout time.Duration) (HandshakeInfo, error) {
	raw, err := recvMySQLPacket(conn, timeout)
	if err != nil {
		return HandshakeInfo{}, err
	}
	if len(raw) == 0 {
		return HandshakeInfo{}, fmt.Errorf("empty mysql greeting")
	}
	return parseMySQLGreeting(raw)
}

func recvMySQLPacket(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if length <= 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("invalid mysql packet length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+length)
	out = append(out, header...)
	out = append(out, payload...)
	return out, nil
}

func parseMySQLGreeting(packet []byte) (HandshakeInfo, error) {
	if len(packet) < 5 {
		return HandshakeInfo{}, fmt.Errorf("mysql packet too short")
	}
	if packet[4] == mysqlErrorHeader {
		return parseMySQLErrorPacket(packet)
	}
	return parseMySQLHandshakePacket(packet)
}

func parseMySQLErrorPacket(packet []byte) (HandshakeInfo, error) {
	// Stay compatible with fingerprintx error detection: minimum size and 0xff header.
	if len(packet) < 8 {
		return HandshakeInfo{}, fmt.Errorf("mysql error packet too short")
	}
	length := mysqlPacketLength(packet)
	if length < 3 || length+4 > len(packet) {
		return HandshakeInfo{}, fmt.Errorf("mysql error packet truncated")
	}
	if packet[4] != mysqlErrorHeader {
		return HandshakeInfo{}, fmt.Errorf("mysql error packet has invalid header")
	}

	info := HandshakeInfo{
		PacketType: "error",
		ErrorCode:  int(binary.LittleEndian.Uint16(packet[5:7])),
	}
	msgStart := 7
	// Protocol 4.1 error packets may include '#' + 5-byte SQLSTATE.
	if 4+length > 8 && packet[7] == '#' && 4+length >= 13 {
		msgStart = 13
	}
	if msgStart < 4+length {
		info.ErrorMessage = readPrintableASCII(packet[msgStart : 4+length])
	}
	return info, nil
}

func parseMySQLHandshakePacket(packet []byte) (HandshakeInfo, error) {
	// Phase 1: fingerprintx-compatible version detection. This must succeed
	// whenever fingerprintx.CheckInitialHandshakePacket would, so Version is
	// never lost to stricter extended parsing.
	version, versionEnd, err := detectMySQLVersion(packet)
	if err != nil {
		return HandshakeInfo{}, err
	}

	info := HandshakeInfo{
		PacketType:      "handshake",
		ProtocolVersion: mysqlProtocolVersion10,
		Version:         version,
	}

	// Phase 2: best-effort enrichment. Failures here must not drop Version.
	enrichMySQLHandshake(&info, packet, versionEnd)
	return info, nil
}

// detectMySQLVersion mirrors fingerprintx CheckInitialHandshakePacket so we
// accept the same greetings and always surface the server version string.
func detectMySQLVersion(packet []byte) (string, int, error) {
	if len(packet) < 35 {
		return "", 0, fmt.Errorf("mysql handshake packet too short")
	}

	// fingerprintx treats bytes[0:4] as little-endian length (seq usually 0).
	// Use the real 3-byte MySQL length for bounds, but keep the same 25..4096 gate.
	length := mysqlPacketLength(packet)
	if length < 25 || length > 4096 {
		return "", 0, fmt.Errorf("mysql handshake packet length out of range")
	}
	if packet[4] != mysqlProtocolVersion10 {
		return "", 0, fmt.Errorf("unsupported mysql protocol version")
	}

	version, nullPos, err := readNullTerminatedASCIIString(packet, 5)
	if err != nil {
		return "", 0, err
	}
	// nullPos points at the NUL; fingerprintx filler is at nullPos+13.
	fillerPos := nullPos + 13
	if fillerPos >= len(packet) {
		return "", 0, fmt.Errorf("mysql handshake missing filler byte")
	}
	if packet[fillerPos] != 0x00 {
		return "", 0, fmt.Errorf("mysql handshake filler byte is not zero")
	}
	return version, nullPos + 1, nil
}

func enrichMySQLHandshake(info *HandshakeInfo, packet []byte, versionEnd int) {
	length := mysqlPacketLength(packet)
	if length+4 > len(packet) {
		length = len(packet) - 4
	}
	if length <= 0 {
		return
	}
	payload := packet[4 : 4+length]
	// versionEnd is absolute index of first byte after version NUL in packet.
	pos := versionEnd - 4
	if pos < 0 || pos > len(payload) {
		return
	}

	if pos+4 > len(payload) {
		return
	}
	info.ThreadID = binary.LittleEndian.Uint32(payload[pos : pos+4])
	pos += 4

	if pos+9 > len(payload) {
		return
	}
	saltPart1 := append([]byte(nil), payload[pos:pos+8]...)
	pos += 8
	if payload[pos] != 0x00 {
		return
	}
	pos++

	if pos+2 > len(payload) {
		return
	}
	capLower := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2

	var capUpper uint16
	var status uint16
	var charset uint8
	authDataLen := 0
	if pos < len(payload) {
		charset = payload[pos]
		pos++
	}
	if pos+2 <= len(payload) {
		status = binary.LittleEndian.Uint16(payload[pos : pos+2])
		pos += 2
	}
	if pos+2 <= len(payload) {
		capUpper = binary.LittleEndian.Uint16(payload[pos : pos+2])
		pos += 2
	}
	if pos < len(payload) {
		authDataLen = int(payload[pos])
		pos++
	}
	if pos+10 <= len(payload) {
		pos += 10
	} else {
		pos = len(payload)
	}

	caps := uint32(capLower) | uint32(capUpper)<<16
	info.CapabilityFlags = caps
	info.Capabilities = decodeCapabilityFlags(caps)
	info.CharacterSet = charset
	info.StatusFlags = status
	info.Status = decodeStatusFlags(status)
	info.AuthPluginDataLen = authDataLen

	part2Len := 13
	if authDataLen > 8 {
		part2Len = authDataLen - 8
	}
	if part2Len < 0 {
		part2Len = 0
	}
	if pos+part2Len > len(payload) {
		part2Len = len(payload) - pos
	}
	if part2Len < 0 {
		part2Len = 0
	}
	saltPart2 := append([]byte(nil), payload[pos:pos+part2Len]...)
	pos += part2Len
	saltPart2 = bytesTrimRightNull(saltPart2)
	info.Salt = formatSalt(append(saltPart1, saltPart2...))

	if caps&clientPluginAuth != 0 && pos < len(payload) {
		if plugin, _, err := readNullTerminatedASCIIString(payload, pos); err == nil {
			info.AuthPluginName = plugin
		}
	}
}

func mysqlPacketLength(packet []byte) int {
	if len(packet) < 3 {
		return 0
	}
	return int(uint32(packet[0]) | uint32(packet[1])<<8 | uint32(packet[2])<<16)
}

// readNullTerminatedASCIIString mirrors fingerprintx: printable ASCII only,
// returns the index of the NUL terminator (not the next byte).
func readNullTerminatedASCIIString(buf []byte, start int) (string, int, error) {
	if start < 0 || start >= len(buf) {
		return "", 0, fmt.Errorf("invalid string offset")
	}
	var characters []byte
	for position := start; position < len(buf); position++ {
		c := buf[position]
		if c >= 0x20 && c <= 0x7e {
			characters = append(characters, c)
			continue
		}
		if c == 0x00 {
			return string(characters), position, nil
		}
		return "", 0, fmt.Errorf("encountered invalid ASCII character")
	}
	return "", 0, fmt.Errorf("unterminated mysql string")
}

func readPrintableASCII(buf []byte) string {
	var characters []byte
	for _, c := range buf {
		if c >= 0x20 && c <= 0x7e {
			characters = append(characters, c)
		}
	}
	return string(characters)
}

func bytesTrimRightNull(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x00 {
		b = b[:len(b)-1]
	}
	return b
}

func formatSalt(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e && c != '\\' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('\\')
		sb.WriteByte('x')
		sb.WriteString(hex.EncodeToString([]byte{c}))
	}
	return sb.String()
}

func decodeCapabilityFlags(caps uint32) []string {
	out := make([]string, 0, len(mysqlCapabilityNames))
	for _, item := range mysqlCapabilityNames {
		if caps&item.flag != 0 {
			out = append(out, item.name)
		}
	}
	return out
}

func decodeStatusFlags(status uint16) []string {
	out := make([]string, 0, len(mysqlStatusNames))
	for _, item := range mysqlStatusNames {
		if status&item.flag != 0 {
			out = append(out, item.name)
		}
	}
	return out
}

func handshakeToJSON(info HandshakeInfo) string {
	bin, err := json.Marshal(info)
	if err != nil {
		return ""
	}
	return string(bin)
}
