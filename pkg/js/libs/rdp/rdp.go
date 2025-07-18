package rdp

import (
	"context"
	"fmt"
	"net"
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
	// RDPEncryptionResponse is the response from the CheckRDPEncryption function.
	// This is returned by CheckRDPEncryption function.
	// @example
	// ```javascript
	// const rdp = require('nuclei/rdp');
	// const encryption = rdp.CheckRDPEncryption('acme.com', 3389);
	// log(toJSON(encryption));
	// ```
	RDPEncryptionResponse struct {
		SecurityLayer struct {
			NativeRDP                bool
			SSL                      bool
			CredSSP                  bool
			RDSTLS                   bool
			CredSSPWithEarlyUserAuth bool
		}
		EncryptionLevel struct {
			RC4_40bit  bool
			RC4_56bit  bool
			RC4_128bit bool
			FIPS140_1  bool
		}
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
func CheckRDPEncryption(host string, port int) (RDPEncryptionResponse, error) {
	return memoizedcheckRDPEncryption(host, port)
}

// @memo
func checkRDPEncryption(host string, port int) (RDPEncryptionResponse, error) {
	resp := RDPEncryptionResponse{}
	timeout := 5 * time.Second

	// Test different security protocols
	protocols := map[string]int{
		"NativeRDP":                0,
		"SSL":                      1,
		"CredSSP":                  3,
		"RDSTLS":                   4,
		"CredSSPWithEarlyUserAuth": 8,
	}

	for name, value := range protocols {
		conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			continue
		}
		defer conn.Close()

		// Test protocol
		isRDP, err := testRDPProtocol(conn, timeout, value)
		if err == nil && isRDP {
			switch name {
			case "NativeRDP":
				resp.SecurityLayer.NativeRDP = true
			case "SSL":
				resp.SecurityLayer.SSL = true
			case "CredSSP":
				resp.SecurityLayer.CredSSP = true
			case "RDSTLS":
				resp.SecurityLayer.RDSTLS = true
			case "CredSSPWithEarlyUserAuth":
				resp.SecurityLayer.CredSSPWithEarlyUserAuth = true
			}
		}
	}

	// Test different encryption levels
	ciphers := map[string]int{
		"RC4_40bit":  1,
		"RC4_56bit":  8,
		"RC4_128bit": 2,
		"FIPS140_1":  16,
	}

	for name, value := range ciphers {
		conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			continue
		}
		defer conn.Close()

		// Test cipher
		isRDP, err := testRDPCipher(conn, timeout, value)
		if err == nil && isRDP {
			switch name {
			case "RC4_40bit":
				resp.EncryptionLevel.RC4_40bit = true
			case "RC4_56bit":
				resp.EncryptionLevel.RC4_56bit = true
			case "RC4_128bit":
				resp.EncryptionLevel.RC4_128bit = true
			case "FIPS140_1":
				resp.EncryptionLevel.FIPS140_1 = true
			}
		}
	}

	return resp, nil
}

// testRDPProtocol tests RDP with a specific security protocol
func testRDPProtocol(conn net.Conn, timeout time.Duration, protocol int) (bool, error) {
	// Set connection timeout
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

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
func testRDPCipher(conn net.Conn, timeout time.Duration, cipher int) (bool, error) {
	// Set connection timeout
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

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
