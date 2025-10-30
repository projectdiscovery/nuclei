package rdp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rdp"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// IsRDPResponse is the response from the IsRDP function.
	// this is returned by IsRDP function.
	// @example
	// ```javascript
	// const rdp = require('nuclei/rdp');
	// const isRDP = rdp.IsRDP('acme.com', 3389);
	// log(toJSON(isRDP));
	// ```
	IsRDPResponse struct {
		IsRDP bool
		OS    string
	}
)

// IsRDP checks if the given host and port are running rdp server.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The Name of the OS is also returned if the connection is successful.
// @example
// ```javascript
// const rdp = require('nuclei/rdp');
// const isRDP = rdp.IsRDP('acme.com', 3389);
// log(toJSON(isRDP));
// ```
func IsRDP(ctx context.Context, host string, port int) (IsRDPResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisRDP(executionId, host, port)
}

// @memo
func isRDP(executionId string, host string, port int) (IsRDPResponse, error) {
	resp := IsRDPResponse{}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsRDPResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	timeout := 5 * time.Second
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	server, isRDP, err := rdp.DetectRDP(conn, timeout)
	if err != nil {
		return resp, err
	}
	if !isRDP {
		return resp, nil
	}
	resp.IsRDP = true
	resp.OS = server
	return resp, nil
}

type (
	// CheckRDPAuthResponse is the response from the CheckRDPAuth function.
	// this is returned by CheckRDPAuth function.
	// @example
	// ```javascript
	// const rdp = require('nuclei/rdp');
	// const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
	// log(toJSON(checkRDPAuth));
	// ```
	CheckRDPAuthResponse struct {
		PluginInfo *plugins.ServiceRDP
		Auth       bool
	}
)

// CheckRDPAuth checks if the given host and port are running rdp server
// with authentication and returns their metadata.
// If connection is successful, it returns true.
// @example
// ```javascript
// const rdp = require('nuclei/rdp');
// const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
// log(toJSON(checkRDPAuth));
// ```
func CheckRDPAuth(ctx context.Context, host string, port int) (CheckRDPAuthResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedcheckRDPAuth(executionId, host, port)
}

// @memo
func checkRDPAuth(executionId string, host string, port int) (CheckRDPAuthResponse, error) {
	resp := CheckRDPAuthResponse{}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return CheckRDPAuthResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	timeout := 5 * time.Second
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	pluginInfo, auth, err := rdp.DetectRDPAuth(conn, timeout)
	if err != nil {
		return resp, err
	}
	if !auth {
		return resp, nil
	}
	resp.Auth = true
	resp.PluginInfo = pluginInfo
	return resp, nil
}

type (
	SecurityLayer string
)

const (
	SecurityLayerNativeRDP                = "NativeRDP"
	SecurityLayerSSL                      = "SSL"
	SecurityLayerCredSSP                  = "CredSSP"
	SecurityLayerRDSTLS                   = "RDSTLS"
	SecurityLayerCredSSPWithEarlyUserAuth = "CredSSPWithEarlyUserAuth"
)

type (
	EncryptionLevel string
)

const (
	EncryptionLevelRC4_40bit  = "RC4_40bit"
	EncryptionLevelRC4_56bit  = "RC4_56bit"
	EncryptionLevelRC4_128bit = "RC4_128bit"
	EncryptionLevelFIPS140_1  = "FIPS140_1"
)

type (
	// RDPEncryptionResponse is the response from the CheckRDPEncryption function.
	// This is returned by CheckRDPEncryption function.
	// @example
	// ```javascript
	// const rdp = require('nuclei/rdp');
	// const encryption = rdp.CheckRDPEncryption('acme.com', 3389);
	// log(toJSON(encryption));
	// ```
	RDPEncryptionResponse struct {
		// Protocols
		NativeRDP                bool
		SSL                      bool
		CredSSP                  bool
		RDSTLS                   bool
		CredSSPWithEarlyUserAuth bool

		// EncryptionLevels
		RC4_40bit  bool
		RC4_56bit  bool
		RC4_128bit bool
		FIPS140_1  bool
	}
)

// CheckRDPEncryption checks the RDP server's supported security layers and encryption levels.
// It tests different protocols and ciphers to determine what is supported.
// @example
// ```javascript
// const rdp = require('nuclei/rdp');
// const encryption = rdp.CheckRDPEncryption('acme.com', 3389);
// log(toJSON(encryption));
// ```
func CheckRDPEncryption(ctx context.Context, host string, port int) (RDPEncryptionResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedcheckRDPEncryption(executionId, host, port)
}

// @memo
func checkRDPEncryption(executionId string, host string, port int) (RDPEncryptionResponse, error) {
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return RDPEncryptionResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	resp := RDPEncryptionResponse{}
	defaultTimeout := 5 * time.Second

	// Test different security protocols
	protocols := map[SecurityLayer]int{
		SecurityLayerNativeRDP:                0,
		SecurityLayerSSL:                      1,
		SecurityLayerCredSSP:                  3,
		SecurityLayerRDSTLS:                   4,
		SecurityLayerCredSSPWithEarlyUserAuth: 8,
	}

	for name, value := range protocols {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		defer func() {
			_ = conn.Close()
		}()

		// Test protocol
		isRDP, err := testRDPProtocol(conn, value)
		if err == nil && isRDP {
			switch SecurityLayer(name) {
			case SecurityLayerNativeRDP:
				resp.NativeRDP = true
			case SecurityLayerSSL:
				resp.SSL = true
			case SecurityLayerCredSSP:
				resp.CredSSP = true
			case SecurityLayerRDSTLS:
				resp.RDSTLS = true
			case SecurityLayerCredSSPWithEarlyUserAuth:
				resp.CredSSPWithEarlyUserAuth = true
			}
		}
	}

	// Test different encryption levels
	ciphers := map[EncryptionLevel]int{
		EncryptionLevelRC4_40bit:  1,
		EncryptionLevelRC4_56bit:  8,
		EncryptionLevelRC4_128bit: 2,
		EncryptionLevelFIPS140_1:  16,
	}

	for encryptionLevel, value := range ciphers {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		defer func() {
			_ = conn.Close()
		}()

		// Test cipher
		isRDP, err := testRDPCipher(conn, value)
		if err == nil && isRDP {
			switch encryptionLevel {
			case EncryptionLevelRC4_40bit:
				resp.RC4_40bit = true
			case EncryptionLevelRC4_56bit:
				resp.RC4_56bit = true
			case EncryptionLevelRC4_128bit:
				resp.RC4_128bit = true
			case EncryptionLevelFIPS140_1:
				resp.FIPS140_1 = true
			}
		}
	}

	return resp, nil
}

// testRDPProtocol tests RDP with a specific security protocol
func testRDPProtocol(conn net.Conn, protocol int) (bool, error) {
	// Send RDP connection request with specific protocol
	// This is a simplified version - in reality you'd need to implement the full RDP protocol
	// including the negotiation phase with the specified protocol
	_, err := conn.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, byte(protocol), 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00})
	if err != nil {
		return false, err
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	// Check if response indicates RDP
	if n >= 19 && buf[0] == 0x03 && buf[1] == 0x00 && buf[2] == 0x00 {
		// For CredSSP and CredSSP with Early User Auth, we need to check for NLA support
		if protocol == 3 || protocol == 8 {
			// Check for NLA support in the response
			if n >= 19 && buf[18]&0x01 != 0 {
				return true, nil
			}
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// testRDPCipher tests RDP with a specific encryption level
func testRDPCipher(conn net.Conn, cipher int) (bool, error) {
	// Send RDP connection request with specific cipher
	// This is a simplified version - in reality you'd need to implement the full RDP protocol
	// including the negotiation phase with the specified cipher
	_, err := conn.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, byte(cipher), 0x03, 0x00, 0x00, 0x00})
	if err != nil {
		return false, err
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	// Check if response indicates RDP
	if n >= 19 && buf[0] == 0x03 && buf[1] == 0x00 && buf[2] == 0x00 {
		// Check for encryption level support in the response
		if n >= 19 && buf[18]&byte(cipher) != 0 {
			return true, nil
		}
		return false, nil
	}

	return false, nil
}
