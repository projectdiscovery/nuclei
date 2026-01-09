package telnetmini

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/Azure/go-ntlmssp"
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
	_ = buf.WriteByte(0x00)

	// Byte count
	_ = buf.WriteByte(0x00)

	// Dialect strings
	dialects := []string{
		"NT LM 0.12",
		"SMB 2.002",
		"SMB 2.???",
	}

	for _, dialect := range dialects {
		_ = buf.WriteByte(byte(len(dialect)))
		_, _ = buf.WriteString(dialect)
		_ = buf.WriteByte(0x00)
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
	_ = buf.WriteByte(0x0D)

	// AndXCommand (no chained command)
	_ = buf.WriteByte(0xFF)

	// AndXReserved
	_ = buf.WriteByte(0x00)

	// AndXOffset
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))

	// MaxBufferSize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0xFFFF))

	// MaxMpxCount
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x01))

	// VcNumber
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x00))

	// SessionKey
	_ = binary.Write(&buf, binary.LittleEndian, uint32(sessionKey))

	// CaseInsensitivePasswordLength
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(password)))

	// CaseSensitivePasswordLength
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(password)))

	// Reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00))

	// Capabilities
	_ = binary.Write(&buf, binary.LittleEndian, uint32(SMB_CAP_EXTENDED_SECURITY|SMB_CAP_NT_SMBS))

	// Byte count
	_ = buf.WriteByte(0x00)

	// CaseInsensitivePassword
	_, _ = buf.WriteString(password)

	// CaseSensitivePassword
	_, _ = buf.WriteString(password)

	// Account name
	_, _ = buf.WriteString(username)
	_ = buf.WriteByte(0x00)

	// Primary domain
	_, _ = buf.WriteString(domain)
	_ = buf.WriteByte(0x00)

	// Native OS
	_, _ = buf.WriteString("Windows 2000 2195")
	_ = buf.WriteByte(0x00)

	// Native LAN Manager
	_, _ = buf.WriteString("Windows 2000 5.0")
	_ = buf.WriteByte(0x00)

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
	_ = buf.WriteByte(0x04)

	// AndXCommand (no chained command)
	_ = buf.WriteByte(0xFF)

	// AndXReserved
	_ = buf.WriteByte(0x00)

	// AndXOffset
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))

	// Flags
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x00))

	// Password length
	_ = buf.WriteByte(byte(len(password)))

	// Byte count
	_ = buf.WriteByte(0x00)

	// Password
	_, _ = buf.WriteString(password)
	_ = buf.WriteByte(0x00)

	// Tree
	_, _ = buf.WriteString(shareName)
	_ = buf.WriteByte(0x00)

	// Service
	_, _ = buf.WriteString("?????")
	_ = buf.WriteByte(0x00)

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
	_ = buf.WriteByte(0x18)

	// AndXCommand (no chained command)
	_ = buf.WriteByte(0xFF)

	// AndXReserved
	_ = buf.WriteByte(0x00)

	// AndXOffset
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))

	// Reserved
	_ = buf.WriteByte(0x00)

	// NameLength
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(fileName)))

	// Flags
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// RootDirectoryFID
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// DesiredAccess
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// AllocationSize
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0x0000000000000000))

	// FileAttributes
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// ShareAccess
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// CreateDisposition
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000001)) // FILE_OPEN

	// CreateOptions
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// ImpersonationLevel
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000002)) // SecurityImpersonation

	// SecurityFlags
	_ = buf.WriteByte(0x00)

	// Byte count
	_ = buf.WriteByte(0x00)

	// SecurityDescriptor
	_ = buf.WriteByte(0x00)

	// FileName
	_, _ = buf.WriteString(fileName)
	_ = buf.WriteByte(0x00)

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
	_, _ = buf.WriteString("NTLMSSP")
	_ = buf.WriteByte(0x00)

	// Message type (1 = Negotiate)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))

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
	_ = binary.Write(&buf, binary.LittleEndian, flags)

	// Domain name fields (empty for negotiate)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // DomainNameLen
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // DomainNameMaxLen
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // DomainNameBufferOffset

	// Workstation name fields (empty for negotiate)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // WorkstationNameLen
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // WorkstationNameMaxLen
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // WorkstationNameBufferOffset

	// Version
	_ = buf.WriteByte(0x05)                                     // Major version
	_ = buf.WriteByte(0x02)                                     // Minor version
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0A28)) // Build number
	_, _ = buf.Write(make([]byte, 3))                           // Reserved
	_ = buf.WriteByte(0x0F)                                     // NTLM revision

	return buf.Bytes()
}

// CreateNTLMChallengePacket creates an NTLM challenge packet (for testing)
func CreateNTLMChallengePacket(challenge []byte, targetInfo []byte) []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	_, _ = buf.WriteString("NTLMSSP")
	_ = buf.WriteByte(0x00)

	// Message type (2 = Challenge)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))

	// Target name fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(56)) // TargetNameBufferOffset

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
	_ = binary.Write(&buf, binary.LittleEndian, flags)

	// Challenge
	_, _ = buf.Write(challenge)

	// Reserved
	_, _ = buf.Write(make([]byte, 8))

	// Target info fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(targetInfo)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(targetInfo)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(56)) // TargetInfoBufferOffset

	// Version
	_ = buf.WriteByte(0x05)                                     // Major version
	_ = buf.WriteByte(0x02)                                     // Minor version
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0A28)) // Build number
	_, _ = buf.Write(make([]byte, 3))                           // Reserved
	_ = buf.WriteByte(0x0F)                                     // NTLM revision

	// Target info
	_, _ = buf.Write(targetInfo)

	return buf.Bytes()
}

// CreateNTLMAuthPacket creates an NTLM authenticate packet
func CreateNTLMAuthPacket(username, password, domain, workstation string, challenge []byte, lmResponse, ntResponse []byte) []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	_, _ = buf.WriteString("NTLMSSP")
	_ = buf.WriteByte(0x00)

	// Message type (3 = Authenticate)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))

	// Calculate offsets
	baseOffset := uint32(72) // Header size (assuming Version is present)

	lmOffset := baseOffset
	ntOffset := lmOffset + uint32(len(lmResponse))
	domainOffset := ntOffset + uint32(len(ntResponse))
	userOffset := domainOffset + uint32(len(domain))
	workOffset := userOffset + uint32(len(username))
	sessionKeyOffset := workOffset + uint32(len(workstation))

	// LM response fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(lmOffset))

	// NT response fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(ntResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(ntResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(ntOffset))

	// Domain name fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(domain)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(domain)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(domainOffset))

	// Username fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(username)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(username)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(userOffset))

	// Workstation name fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(workstation)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(workstation)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(workOffset))

	// Encrypted random session key fields
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(sessionKeyOffset))

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
	_ = binary.Write(&buf, binary.LittleEndian, flags)

	// Version
	_ = buf.WriteByte(0x05)                                     // Major version
	_ = buf.WriteByte(0x02)                                     // Minor version
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0A28)) // Build number
	_, _ = buf.Write(make([]byte, 3))                           // Reserved
	_ = buf.WriteByte(0x0F)                                     // NTLM revision

	// LM response
	_, _ = buf.Write(lmResponse)

	// NT response
	_, _ = buf.Write(ntResponse)

	// Domain name
	_, _ = buf.WriteString(domain)

	// Username
	_, _ = buf.WriteString(username)

	// Workstation name
	_, _ = buf.WriteString(workstation)

	return buf.Bytes()
}

// Helper function to create LM hash response
func CreateLMResponse(challenge []byte, password string) []byte {
	// Create a minimal Type 2 challenge packet to satisfy ntlmssp
	type2 := CreateNTLMChallengePacket(challenge, []byte{})

	// Generate Type 3 authenticate packet
	// We use empty username/domain as we only need the hash response
	authMsg, err := ntlmssp.NewAuthenticateMessage(type2, "", password, nil)
	if err != nil {
		return nil
	}

	// Parse the response to extract LM response
	// LM Response Len is at offset 12 (2 bytes)
	// LM Response Offset is at offset 16 (4 bytes)
	if len(authMsg) < 20 {
		return nil
	}

	lmLen := binary.LittleEndian.Uint16(authMsg[12:14])
	lmOffset := binary.LittleEndian.Uint32(authMsg[16:20])

	if int(lmOffset)+int(lmLen) > len(authMsg) {
		return nil
	}

	return authMsg[lmOffset : lmOffset+uint32(lmLen)]
}

// Helper function to create NT hash response
func CreateNTResponse(challenge []byte, password string) []byte {
	// Create a minimal Type 2 challenge packet to satisfy ntlmssp
	type2 := CreateNTLMChallengePacket(challenge, []byte{})

	// Generate Type 3 authenticate packet
	authMsg, err := ntlmssp.NewAuthenticateMessage(type2, "", password, nil)
	if err != nil {
		return nil
	}

	// Parse the response to extract NT response
	// NT Response Len is at offset 20 (2 bytes)
	// NT Response Offset is at offset 24 (4 bytes)
	if len(authMsg) < 28 {
		return nil
	}

	ntLen := binary.LittleEndian.Uint16(authMsg[20:22])
	ntOffset := binary.LittleEndian.Uint32(authMsg[24:28])

	if int(ntOffset)+int(ntLen) > len(authMsg) {
		return nil
	}

	return authMsg[ntOffset : ntOffset+uint32(ntLen)]
}

// CreateSMBv2NegotiatePacket creates an SMBv2 negotiate protocol packet
func CreateSMBv2NegotiatePacket() []byte {
	var buf bytes.Buffer

	// SMB2 header
	_ = buf.WriteByte(0xFE) // Protocol ID
	_, _ = buf.WriteString("SMB")
	_ = buf.WriteByte(0x00) // Protocol ID

	// Command (Negotiate Protocol)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0000))

	// Status
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// Flags
	_ = buf.WriteByte(0x00)

	// Next command
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0000))

	// Message ID
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0x0000000000000001))

	// Reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// Tree ID
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000000))

	// Session ID
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0x0000000000000000))

	// Signature
	_, _ = buf.Write(make([]byte, 16))

	// Structure size
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x24))

	// Dialect count
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0001))

	// Security mode
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0001))

	// Reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0000))

	// Capabilities
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000001))

	// Client GUID
	_, _ = buf.Write(make([]byte, 16))

	// Client start time
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0x0000000000000000))

	// Dialects
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0311)) // SMB 3.1.1

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
