package telnetmini

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// SMB constants for packet crafting
const (
	// SMB Commands
	SMB_COM_NEGOTIATE_PROTOCOL = 0x72
	SMB_COM_SESSION_SETUP_ANDX = 0x73
	SMB_COM_TREE_CONNECT_ANDX  = 0x75
	SMB_COM_NT_CREATE_ANDX     = 0xA2
	SMB_COM_READ_ANDX          = 0x2E
	SMB_COM_WRITE_ANDX         = 0x2F
	SMB_COM_CLOSE              = 0x04
	SMB_COM_TREE_DISCONNECT    = 0x71
	SMB_COM_LOGOFF_ANDX        = 0x74

	// SMB Flags
	SMB_FLAGS_CANONICAL_PATHNAMES              = 0x10
	SMB_FLAGS_CASELESS_PATHNAMES               = 0x08
	SMB_FLAGS2_UNICODE_STRINGS                 = 0x8000
	SMB_FLAGS2_ERRSTATUS                       = 0x4000
	SMB_FLAGS2_READ_IF_EXECUTE                 = 0x2000
	SMB_FLAGS2_32_BIT_ERRORS                   = 0x1000
	SMB_FLAGS2_DFS                             = 0x0800
	SMB_FLAGS2_EXTENDED_SECURITY               = 0x0400
	SMB_FLAGS2_REPARSE_PATH                    = 0x0200
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE          = 0x0100
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED = 0x0080

	// SMB Security modes
	SMB_SECURITY_SHARE  = 0x00
	SMB_SECURITY_USER   = 0x01
	SMB_SECURITY_DOMAIN = 0x02

	// SMB Capabilities
	SMB_CAP_EXTENDED_SECURITY  = 0x80000000
	SMB_CAP_COMPRESSED_DATA    = 0x40000000
	SMB_CAP_BULK_TRANSFER      = 0x20000000
	SMB_CAP_UNIX               = 0x00800000
	SMB_CAP_LARGE_READX        = 0x00400000
	SMB_CAP_LARGE_WRITEX       = 0x00200000
	SMB_CAP_INFOLEVEL_PASSTHRU = 0x00100000
	SMB_CAP_DFS                = 0x00080000
	SMB_CAP_NT_FIND            = 0x00040000
	SMB_CAP_LOCK_AND_READ      = 0x00020000
	SMB_CAP_LEVEL_II_OPLOCKS   = 0x00010000
	SMB_CAP_STATUS32           = 0x00008000
	SMB_CAP_RPC_REMOTE_APIS    = 0x00004000
	SMB_CAP_NT_SMBS            = 0x00002000

	// NTLM constants
	NTLMSSP_NEGOTIATE_56                        = 0x80000000
	NTLMSSP_NEGOTIATE_KEY_EXCH                  = 0x40000000
	NTLMSSP_NEGOTIATE_128                       = 0x20000000
	NTLMSSP_NEGOTIATE_VERSION                   = 0x02000000
	NTLMSSP_NEGOTIATE_TARGET_INFO               = 0x00800000
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY          = 0x00400000
	NTLMSSP_NEGOTIATE_IDENTIFY                  = 0x00100000
	NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000
	NTLMSSP_TARGET_TYPE_SERVER                  = 0x00020000
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN               = 0x00008000
	NTLMSSP_NEGOTIATE_NTLM                      = 0x00000200
	NTLMSSP_NEGOTIATE_LM_KEY                    = 0x00000080
	NTLMSSP_NEGOTIATE_DATAGRAM                  = 0x00000040
	NTLMSSP_NEGOTIATE_SEAL                      = 0x00000020
	NTLMSSP_NEGOTIATE_SIGN                      = 0x00000010
	NTLMSSP_REQUEST_TARGET                      = 0x00000004
	NTLMSSP_NEGOTIATE_UNICODE                   = 0x00000001
)

// SMBPacket represents a complete SMB packet
type SMBPacket struct {
	NetBIOSHeader []byte
	SMBHeader     []byte
	SMBData       []byte
}

// SMBHeader represents the SMB header structure
type SMBHeader struct {
	ProtocolID  [4]byte // 0xFF, 'S', 'M', 'B'
	Command     byte
	Status      uint32
	Flags       byte
	Flags2      uint16
	PIDHigh     uint16
	Signature   [8]byte
	Reserved    uint16
	TreeID      uint16
	ProcessID   uint16
	UserID      uint16
	MultiplexID uint16
}

// CreateSMBPacket creates a complete SMB packet with NetBIOS header
func CreateSMBPacket(smbData []byte) *SMBPacket {
	// Create NetBIOS header
	netbiosHeader := make([]byte, 4)
	netbiosHeader[0] = 0x00 // Message type (Session message)
	netbiosHeader[1] = 0x00 // Padding
	netbiosHeader[2] = 0x00 // Padding

	// Calculate NetBIOS length (big-endian)
	length := len(smbData)
	netbiosHeader[3] = byte(length & 0xFF)

	return &SMBPacket{
		NetBIOSHeader: netbiosHeader,
		SMBHeader:     createSMBHeader(),
		SMBData:       smbData,
	}
}

// createSMBHeader creates a standard SMB header
func createSMBHeader() []byte {
	header := make([]byte, 32)

	// Protocol ID: 0xFF, 'S', 'M', 'B'
	header[0] = 0xFF
	header[1] = 'S'
	header[2] = 'M'
	header[3] = 'B'

	// Command (will be set by caller)
	header[4] = 0x00

	// Status (0 for requests)
	binary.LittleEndian.PutUint32(header[5:9], 0)

	// Flags
	header[9] = SMB_FLAGS_CANONICAL_PATHNAMES

	// Flags2
	binary.LittleEndian.PutUint16(header[10:12], SMB_FLAGS2_UNICODE_STRINGS|SMB_FLAGS2_EXTENDED_SECURITY)

	// PIDHigh, Signature, Reserved, TreeID, ProcessID, UserID, MultiplexID
	// All set to 0 for new connections
	binary.LittleEndian.PutUint16(header[12:14], 0) // PIDHigh
	// Signature is 8 bytes of zeros
	binary.LittleEndian.PutUint16(header[20:22], 0) // Reserved
	binary.LittleEndian.PutUint16(header[22:24], 0) // TreeID
	binary.LittleEndian.PutUint16(header[24:26], 0) // ProcessID
	binary.LittleEndian.PutUint16(header[26:28], 0) // UserID
	binary.LittleEndian.PutUint16(header[28:30], 0) // MultiplexID

	return header
}

// CreateNegotiateProtocolPacket creates an SMB negotiate protocol packet
func CreateNegotiateProtocolPacket() []byte {
	// Create SMB header
	header := createSMBHeader()
	header[4] = SMB_COM_NEGOTIATE_PROTOCOL

	// Create negotiate protocol data
	data := createNegotiateProtocolData()

	// Combine header and data
	packet := append(header, data...)

	// Create complete packet with NetBIOS header
	smbPacket := CreateSMBPacket(packet)

	return smbPacket.Bytes()
}

// createNegotiateProtocolData creates the data portion of negotiate protocol packet
func createNegotiateProtocolData() []byte {
	var buf bytes.Buffer

	// Word count
	buf.WriteByte(0x00)

	// Byte count
	buf.WriteByte(0x00)

	// Dialect strings
	dialects := []string{
		"NT LM 0.12",
		"SMB 2.002",
		"SMB 2.???",
	}

	for _, dialect := range dialects {
		buf.WriteByte(byte(len(dialect)))
		buf.WriteString(dialect)
		buf.WriteByte(0x00)
	}

	// Update byte count
	data := buf.Bytes()
	data[1] = byte(len(data) - 2)

	return data
}

// CreateSessionSetupPacket creates an SMB session setup packet
func CreateSessionSetupPacket(username, password, domain string, sessionKey uint64) []byte {
	// Create SMB header
	header := createSMBHeader()
	header[4] = SMB_COM_SESSION_SETUP_ANDX

	// Create session setup data
	data := createSessionSetupData(username, password, domain, sessionKey)

	// Combine header and data
	packet := append(header, data...)

	// Create complete packet with NetBIOS header
	smbPacket := CreateSMBPacket(packet)

	return smbPacket.Bytes()
}

// createSessionSetupData creates the data portion of session setup packet
func createSessionSetupData(username, password, domain string, sessionKey uint64) []byte {
	var buf bytes.Buffer

	// Word count
	buf.WriteByte(0x0D)

	// AndXCommand (no chained command)
	buf.WriteByte(0xFF)

	// AndXReserved
	buf.WriteByte(0x00)

	// AndXOffset
	binary.LittleEndian.PutUint16(buf.Next(2), 0)

	// MaxBufferSize
	binary.LittleEndian.PutUint16(buf.Next(2), 0xFFFF)

	// MaxMpxCount
	binary.LittleEndian.PutUint16(buf.Next(2), 0x01)

	// VcNumber
	binary.LittleEndian.PutUint16(buf.Next(2), 0x00)

	// SessionKey
	binary.LittleEndian.PutUint32(buf.Next(4), uint32(sessionKey))

	// CaseInsensitivePasswordLength
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(password)))

	// CaseSensitivePasswordLength
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(password)))

	// Reserved
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00)

	// Capabilities
	binary.LittleEndian.PutUint32(buf.Next(4), SMB_CAP_EXTENDED_SECURITY|SMB_CAP_NT_SMBS)

	// Byte count
	buf.WriteByte(0x00)

	// CaseInsensitivePassword
	buf.WriteString(password)

	// CaseSensitivePassword
	buf.WriteString(password)

	// Account name
	buf.WriteString(username)
	buf.WriteByte(0x00)

	// Primary domain
	buf.WriteString(domain)
	buf.WriteByte(0x00)

	// Native OS
	buf.WriteString("Windows 2000 2195")
	buf.WriteByte(0x00)

	// Native LAN Manager
	buf.WriteString("Windows 2000 5.0")
	buf.WriteByte(0x00)

	// Update byte count
	data := buf.Bytes()
	data[len(data)-1] = byte(len(data) - 0x21) // 0x21 is the offset to the start of variable data

	return data
}

// CreateTreeConnectPacket creates an SMB tree connect packet
func CreateTreeConnectPacket(shareName string, password string) []byte {
	// Create SMB header
	header := createSMBHeader()
	header[4] = SMB_COM_TREE_CONNECT_ANDX

	// Create tree connect data
	data := createTreeConnectData(shareName, password)

	// Combine header and data
	packet := append(header, data...)

	// Create complete packet with NetBIOS header
	smbPacket := CreateSMBPacket(packet)

	return smbPacket.Bytes()
}

// createTreeConnectData creates the data portion of tree connect packet
func createTreeConnectData(shareName, password string) []byte {
	var buf bytes.Buffer

	// Word count
	buf.WriteByte(0x04)

	// AndXCommand (no chained command)
	buf.WriteByte(0xFF)

	// AndXReserved
	buf.WriteByte(0x00)

	// AndXOffset
	binary.LittleEndian.PutUint16(buf.Next(2), 0)

	// Flags
	binary.LittleEndian.PutUint16(buf.Next(2), 0x00)

	// Password length
	buf.WriteByte(byte(len(password)))

	// Byte count
	buf.WriteByte(0x00)

	// Password
	buf.WriteString(password)
	buf.WriteByte(0x00)

	// Tree
	buf.WriteString(shareName)
	buf.WriteByte(0x00)

	// Service
	buf.WriteString("?????")
	buf.WriteByte(0x00)

	// Update byte count
	data := buf.Bytes()
	data[7] = byte(len(data) - 0x0B) // 0x0B is the offset to the start of variable data

	return data
}

// CreateNTCreatePacket creates an SMB NT create packet
func CreateNTCreatePacket(fileName string) []byte {
	// Create SMB header
	header := createSMBHeader()
	header[4] = SMB_COM_NT_CREATE_ANDX

	// Create NT create data
	data := createNTCreateData(fileName)

	// Combine header and data
	packet := append(header, data...)

	// Create complete packet with NetBIOS header
	smbPacket := CreateSMBPacket(packet)

	return smbPacket.Bytes()
}

// createNTCreateData creates the data portion of NT create packet
func createNTCreateData(fileName string) []byte {
	var buf bytes.Buffer

	// Word count
	buf.WriteByte(0x18)

	// AndXCommand (no chained command)
	buf.WriteByte(0xFF)

	// AndXReserved
	buf.WriteByte(0x00)

	// AndXOffset
	binary.LittleEndian.PutUint16(buf.Next(2), 0)

	// Reserved
	buf.WriteByte(0x00)

	// NameLength
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(fileName)))

	// Flags
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// RootDirectoryFID
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// DesiredAccess
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// AllocationSize
	binary.LittleEndian.PutUint64(buf.Next(8), 0x0000000000000000)

	// FileAttributes
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// ShareAccess
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// CreateDisposition
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000001) // FILE_OPEN

	// CreateOptions
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// ImpersonationLevel
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000002) // SecurityImpersonation

	// SecurityFlags
	buf.WriteByte(0x00)

	// Byte count
	buf.WriteByte(0x00)

	// SecurityDescriptor
	buf.WriteByte(0x00)

	// FileName
	buf.WriteString(fileName)
	buf.WriteByte(0x00)

	// Update byte count
	data := buf.Bytes()
	data[0x3B] = byte(len(data) - 0x3C) // 0x3C is the offset to the start of variable data

	return data
}

// Bytes returns the complete SMB packet as bytes
func (p *SMBPacket) Bytes() []byte {
	var result bytes.Buffer
	result.Write(p.NetBIOSHeader)
	result.Write(p.SMBHeader)
	result.Write(p.SMBData)
	return result.Bytes()
}

// CreateNTLMNegotiatePacket creates an NTLM negotiate packet for SMB authentication
func CreateNTLMNegotiatePacket() []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	buf.WriteString("NTLMSSP")
	buf.WriteByte(0x00)

	// Message type (1 = Negotiate)
	binary.LittleEndian.PutUint32(buf.Next(4), 1)

	// Negotiate flags
	flags := uint32(NTLMSSP_NEGOTIATE_56 |
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY |
		NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_UNICODE)
	binary.LittleEndian.PutUint32(buf.Next(4), flags)

	// Domain name fields (empty for negotiate)
	binary.LittleEndian.PutUint16(buf.Next(2), 0) // DomainNameLen
	binary.LittleEndian.PutUint16(buf.Next(2), 0) // DomainNameMaxLen
	binary.LittleEndian.PutUint32(buf.Next(4), 0) // DomainNameBufferOffset

	// Workstation name fields (empty for negotiate)
	binary.LittleEndian.PutUint16(buf.Next(2), 0) // WorkstationNameLen
	binary.LittleEndian.PutUint16(buf.Next(2), 0) // WorkstationNameMaxLen
	binary.LittleEndian.PutUint32(buf.Next(4), 0) // WorkstationNameBufferOffset

	// Version (empty for negotiate)
	buf.Write(make([]byte, 8))

	return buf.Bytes()
}

// CreateNTLMChallengePacket creates an NTLM challenge packet (for testing)
func CreateNTLMChallengePacket(challenge []byte, targetInfo []byte) []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	buf.WriteString("NTLMSSP")
	buf.WriteByte(0x00)

	// Message type (2 = Challenge)
	binary.LittleEndian.PutUint32(buf.Next(4), 2)

	// Target name fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20) // TargetNameBufferOffset

	// Negotiate flags
	flags := uint32(NTLMSSP_NEGOTIATE_56 |
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY |
		NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_UNICODE)
	binary.LittleEndian.PutUint32(buf.Next(4), flags)

	// Challenge
	buf.Write(challenge)

	// Reserved
	buf.Write(make([]byte, 8))

	// Target info fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x30) // TargetInfoBufferOffset

	// Version
	buf.WriteByte(0x05)                                // Major version
	buf.WriteByte(0x02)                                // Minor version
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0A28) // Build number
	buf.Write(make([]byte, 3))                         // Reserved
	buf.WriteByte(0x0F)                                // NTLM revision

	// Target info
	buf.Write(targetInfo)

	return buf.Bytes()
}

// CreateNTLMAuthPacket creates an NTLM authenticate packet
func CreateNTLMAuthPacket(username, password, domain, workstation string, challenge []byte, lmResponse, ntResponse []byte) []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	buf.WriteString("NTLMSSP")
	buf.WriteByte(0x00)

	// Message type (3 = Authenticate)
	binary.LittleEndian.PutUint32(buf.Next(4), 3)

	// LM response fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(lmResponse)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(lmResponse)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20) // LMResponseBufferOffset

	// NT response fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20+uint32(len(lmResponse))) // NTResponseBufferOffset

	// Domain name fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(domain)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(domain)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20+uint32(len(lmResponse)+len(ntResponse))) // DomainNameBufferOffset

	// Username fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(username)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(username)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20+uint32(len(lmResponse)+len(ntResponse)+len(domain))) // UserNameBufferOffset

	// Workstation name fields
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(workstation)))
	binary.LittleEndian.PutUint16(buf.Next(2), uint16(len(workstation)))
	binary.LittleEndian.PutUint32(buf.Next(4), 0x20+uint32(len(lmResponse)+len(ntResponse)+len(domain)+len(username))) // WorkstationNameBufferOffset

	// Encrypted random session key fields
	binary.LittleEndian.PutUint16(buf.Next(2), 0)
	binary.LittleEndian.PutUint16(buf.Next(2), 0)
	binary.LittleEndian.PutUint32(buf.Next(4), 0)

	// Negotiate flags
	flags := uint32(NTLMSSP_NEGOTIATE_56 |
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY |
		NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_UNICODE)
	binary.LittleEndian.PutUint32(buf.Next(4), flags)

	// Version
	buf.WriteByte(0x05)                                // Major version
	buf.WriteByte(0x02)                                // Minor version
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0A28) // Build number
	buf.Write(make([]byte, 3))                         // Reserved
	buf.WriteByte(0x0F)                                // NTLM revision

	// LM response
	buf.Write(lmResponse)

	// NT response
	buf.Write(ntResponse)

	// Domain name
	buf.WriteString(domain)

	// Username
	buf.WriteString(username)

	// Workstation name
	buf.WriteString(workstation)

	return buf.Bytes()
}

// Helper function to create LM hash response
func CreateLMResponse(challenge []byte, password string) []byte {
	// This is a simplified implementation
	// In practice, you'd need to implement the full LM hash algorithm
	// For now, return a dummy response
	return make([]byte, 24)
}

// Helper function to create NT hash response
func CreateNTResponse(challenge []byte, password string) []byte {
	// This is a simplified implementation
	// In practice, you'd need to implement the full NT hash algorithm
	// For now, return a dummy response
	return make([]byte, 24)
}

// CreateSMBv2NegotiatePacket creates an SMBv2 negotiate protocol packet
func CreateSMBv2NegotiatePacket() []byte {
	var buf bytes.Buffer

	// SMB2 header
	buf.WriteByte(0xFE) // Protocol ID
	buf.WriteString("SMB")
	buf.WriteByte(0x00) // Protocol ID

	// Command (Negotiate Protocol)
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0000)

	// Status
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// Flags
	buf.WriteByte(0x00)

	// Next command
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0000)

	// Message ID
	binary.LittleEndian.PutUint64(buf.Next(8), 0x0000000000000001)

	// Reserved
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// Tree ID
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000000)

	// Session ID
	binary.LittleEndian.PutUint64(buf.Next(8), 0x0000000000000000)

	// Signature
	buf.Write(make([]byte, 16))

	// Structure size
	binary.LittleEndian.PutUint16(buf.Next(2), 0x24)

	// Dialect count
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0001)

	// Security mode
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0001)

	// Reserved
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0000)

	// Capabilities
	binary.LittleEndian.PutUint32(buf.Next(4), 0x00000001)

	// Client GUID
	buf.Write(make([]byte, 16))

	// Client start time
	binary.LittleEndian.PutUint64(buf.Next(8), 0x0000000000000000)

	// Dialects
	binary.LittleEndian.PutUint16(buf.Next(2), 0x0311) // SMB 3.1.1

	return buf.Bytes()
}

// ParseSMBResponse parses an SMB response packet
func ParseSMBResponse(data []byte) (*SMBHeader, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("SMB response too short: %d bytes", len(data))
	}

	header := &SMBHeader{}

	// Check protocol ID
	if data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, fmt.Errorf("invalid SMB protocol ID")
	}

	// Parse header fields
	header.Command = data[4]
	header.Status = binary.LittleEndian.Uint32(data[5:9])
	header.Flags = data[9]
	header.Flags2 = binary.LittleEndian.Uint16(data[10:12])
	header.PIDHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(header.Signature[:], data[14:22])
	header.Reserved = binary.LittleEndian.Uint16(data[22:24])
	header.TreeID = binary.LittleEndian.Uint16(data[24:26])
	header.ProcessID = binary.LittleEndian.Uint16(data[26:28])
	header.UserID = binary.LittleEndian.Uint16(data[28:30])
	header.MultiplexID = binary.LittleEndian.Uint16(data[30:32])

	return header, nil
}
