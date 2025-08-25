package telnetmini

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NTLMInfoResponse represents the response from NTLM information gathering
// This matches exactly the output structure from the Nmap telnet-ntlm-info.nse script
type NTLMInfoResponse struct {
	TargetName          string // Target_Name from script
	NetBIOSDomainName   string // NetBIOS_Domain_Name from script
	NetBIOSComputerName string // NetBIOS_Computer_Name from script
	DNSDomainName       string // DNS_Domain_Name from script
	DNSComputerName     string // DNS_Computer_Name from script
	DNSTreeName         string // DNS_Tree_Name from script
	ProductVersion      string // Product_Version from script
	Timestamp           uint64 // Raw timestamp for skew calculation
}

// ParseNTLMResponse parses the NTLM response to extract system information
// This implements the exact parsing logic from the Nmap telnet-ntlm-info.nse script
func ParseNTLMResponse(data []byte) (*NTLMInfoResponse, error) {
	// Continue only if NTLMSSP response is returned.
	// Verify that the response is terminated with Sub-option End values as various
	// non Microsoft telnet implementations support NTLM but do not return valid data.
	// This matches the script's: local data = string.match(response, "(NTLMSSP.*)\xff\xf0")
	ntlmStart := bytes.Index(data, []byte("NTLMSSP"))
	if ntlmStart == -1 {
		return nil, fmt.Errorf("NTLMSSP signature not found in response")
	}

	// Find the end of NTLM data (Sub-option End: 0xFF 0xF0)
	ntlmEnd := bytes.Index(data[ntlmStart:], []byte{0xFF, 0xF0})
	if ntlmEnd == -1 {
		return nil, fmt.Errorf("NTLM response not properly terminated with Sub-option End")
	}

	// Extract NTLM data (NTLMSSP.*\xff\xf0)
	ntlmData := data[ntlmStart : ntlmStart+ntlmEnd]

	// Check message type (should be 2 for Challenge)
	if len(ntlmData) < 12 {
		return nil, fmt.Errorf("NTLM response too short")
	}

	messageType := binary.LittleEndian.Uint32(ntlmData[8:12])
	if messageType != 2 {
		return nil, fmt.Errorf("expected NTLM challenge message, got type %d", messageType)
	}

	// Parse target name fields
	targetNameLen := binary.LittleEndian.Uint16(ntlmData[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(ntlmData[16:20])

	// Parse target info fields
	targetInfoLen := binary.LittleEndian.Uint16(ntlmData[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(ntlmData[44:48])

	// Extract target name (Target Name will always be returned under any implementation)
	var targetName string
	if targetNameLen > 0 && int(targetNameOffset) < len(ntlmData) {
		end := int(targetNameOffset) + int(targetNameLen)
		if end <= len(ntlmData) {
			targetName = string(ntlmData[targetNameOffset:end])
		}
	}

	// Extract target info (contains detailed system information)
	var ntlmInfo NTLMInfoResponse
	ntlmInfo.TargetName = targetName

	// Parse target info structure if available
	if targetInfoLen > 0 && int(targetInfoOffset) < len(ntlmData) {
		end := int(targetInfoOffset) + int(targetInfoLen)
		if end <= len(ntlmData) {
			parseTargetInfo(ntlmData[targetInfoOffset:end], &ntlmInfo)
		}
	}

	return &ntlmInfo, nil
}

// CalculateTimestampSkew calculates the time skew from NTLM timestamp
// This implements the timestamp calculation from the Nmap script:
// local unixstamp = ntlm_decoded.timestamp // 10000000 - 11644473600
func CalculateTimestampSkew(ntlmTimestamp uint64) int64 {
	if ntlmTimestamp == 0 {
		return 0
	}

	// Convert 100ns clicks since 1/1/1601 to Unix timestamp
	// Formula: (ntlmTimestamp / 10000000) - 11644473600
	unixTimestamp := int64(ntlmTimestamp/10000000) - 11644473600
	return unixTimestamp
}

// parseTargetInfo parses the NTLM target info structure to extract system details
func parseTargetInfo(data []byte, info *NTLMInfoResponse) {
	// Target info is a series of type-length-value pairs
	// Each entry starts with a 2-byte type and 2-byte length
	for i := 0; i < len(data)-4; {
		if i+4 > len(data) {
			break
		}

		infoType := binary.LittleEndian.Uint16(data[i : i+2])
		infoLen := binary.LittleEndian.Uint16(data[i+2 : i+4])

		if i+4+int(infoLen) > len(data) {
			break
		}

		infoData := data[i+4 : i+4+int(infoLen)]

		switch infoType {
		case 1: // NetBIOS Computer Name
			// Display information returned & ignore responses with null values
			if len(infoData) > 0 {
				info.NetBIOSComputerName = string(infoData)
			}
		case 2: // NetBIOS Domain Name
			if len(infoData) > 0 {
				info.NetBIOSDomainName = string(infoData)
			}
		case 3: // DNS Computer Name (fqdn in script)
			if len(infoData) > 0 {
				info.DNSComputerName = string(infoData)
			}
		case 4: // DNS Domain Name
			if len(infoData) > 0 {
				info.DNSDomainName = string(infoData)
			}
		case 5: // DNS Tree Name (dns_forest_name in script)
			if len(infoData) > 0 {
				info.DNSTreeName = string(infoData)
			}
		case 6: // Timestamp - 64-bit number of 100ns clicks since 1/1/1601
			if len(infoData) >= 8 {
				info.Timestamp = binary.LittleEndian.Uint64(infoData)
			}
		case 7: // Single Host
			// Skip single host
		case 8: // Target Name (target_realm in script)
			if len(infoData) > 0 {
				info.TargetName = string(infoData)
			}
		case 9: // Channel Bindings
			// Skip channel bindings
		case 10: // Target Information
			// Skip target information
		case 11: // OS Version
			if len(infoData) >= 8 {
				major := uint8(infoData[0])
				minor := uint8(infoData[1])
				build := binary.LittleEndian.Uint16(infoData[2:4])
				info.ProductVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
			}
		}

		i += 4 + int(infoLen)
	}
}

// CreateNTLMNegotiateBlob creates the NTLM negotiate blob with specific flags
// This matches the flags used in the Nmap script
func CreateNTLMNegotiateBlob() []byte {
	var buf bytes.Buffer

	// NTLMSSP signature
	buf.WriteString("NTLMSSP")
	buf.WriteByte(0x00)

	// Message type (1 = Negotiate)
	messageTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageTypeBytes, 1)
	buf.Write(messageTypeBytes)

	// Negotiate flags (matching Nmap script exactly)
	flags := uint32(0x00000001 + // Negotiate Unicode
		0x00000002 + // Negotiate OEM strings
		0x00000004 + // Request Target
		0x00000200 + // Negotiate NTLM
		0x00008000 + // Negotiate Always Sign
		0x00080000 + // Negotiate NTLM2 Key
		0x20000000 + // Negotiate 128
		0x80000000) // Negotiate 56
	flagsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagsBytes, flags)
	buf.Write(flagsBytes)

	// Domain name fields (empty for negotiate)
	domainNameLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(domainNameLenBytes, 0)
	buf.Write(domainNameLenBytes)

	domainNameMaxLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(domainNameMaxLenBytes, 0)
	buf.Write(domainNameMaxLenBytes)

	domainNameOffsetBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(domainNameOffsetBytes, 0)
	buf.Write(domainNameOffsetBytes)

	// Workstation name fields (empty for negotiate)
	workstationNameLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(workstationNameLenBytes, 0)
	buf.Write(workstationNameLenBytes)

	workstationNameMaxLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(workstationNameMaxLenBytes, 0)
	buf.Write(workstationNameMaxLenBytes)

	workstationNameOffsetBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(workstationNameOffsetBytes, 0)
	buf.Write(workstationNameOffsetBytes)

	// Version (empty for negotiate)
	buf.Write(make([]byte, 8))

	return buf.Bytes()
}

// CreateTNAPLoginPacket creates the MS-TNAP Login Packet (Option Command IS)
// This implements the exact packet structure from the Nmap script
func CreateTNAPLoginPacket() []byte {
	var buf bytes.Buffer

	// TNAP Option Command IS (0x01)
	buf.WriteByte(0x01)

	// Length (will be updated later)
	buf.WriteByte(0x00)

	// NTLM authentication blob
	ntlmBlob := CreateNTLMNegotiateBlob()

	// Update length
	data := buf.Bytes()
	data[1] = byte(len(ntlmBlob)) // Length of the NTLM blob

	// Append NTLM blob
	buf.Write(ntlmBlob)

	return buf.Bytes()
}
