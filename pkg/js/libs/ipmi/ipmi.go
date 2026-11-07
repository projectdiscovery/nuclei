package ipmi

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
)

type (
	// AuthCapabilities is what a BMC advertises before any login, from Get
	// Channel Authentication Capabilities.
	// @example
	// ```javascript
	// const ipmi = require('nuclei/ipmi');
	// const caps = ipmi.GetAuthCapabilities('acme.com', 623);
	// log(toJSON(caps));
	// ```
	AuthCapabilities struct {
		// IPMI20 is true when the BMC supports IPMI 2.0 (RMCP+).
		IPMI20 bool
		// AuthTypes are the IPMI 1.5 authentication types the channel
		// accepts: none, md2, md5, straight (cleartext password), oem.
		AuthTypes []string
		// AnonymousLogin is true when a null username with a null password
		// is accepted.
		AnonymousLogin bool
		// NullUsernames is true when accounts with an empty name are enabled.
		NullUsernames bool
		// NonNullUsernames is true when named accounts are enabled.
		NonNullUsernames bool
		// PerMessageAuth is false when the BMC skips authenticating
		// messages after login.
		PerMessageAuth bool
		// UserLevelAuth is false when user-level commands skip
		// authentication.
		UserLevelAuth bool
		// OEMID is the IANA enterprise number of the BMC vendor, or 0.
		OEMID int
	}

	// RAKPHash is the HMAC a BMC returns for a user during RMCP+ session
	// setup (CVE-2013-4786). It can be checked offline against candidate
	// passwords, which tests credentials without a login attempt.
	// @example
	// ```javascript
	// const ipmi = require('nuclei/ipmi');
	// const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
	// log(hash.Hashcat);
	// ```
	RAKPHash struct {
		Username string
		// Algorithm is the HMAC the BMC used: sha1 or md5.
		Algorithm string
		// Salt and HMAC are hex encoded; Salt is everything the HMAC covers.
		Salt string
		HMAC string
		// Hashcat is the hash in hashcat mode 7300 format, for sha1 only.
		Hashcat string
	}

	// Client holds one RMCP+ session, for commands that need a login.
	// Close it when done: BMCs allow only a few sessions at a time.
	// @example
	// ```javascript
	// const ipmi = require('nuclei/ipmi');
	// const client = new ipmi.Client();
	// client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
	// const id = client.Command(0x06, 0x01, []);
	// client.Close();
	// ```
	Client struct {
		session *established
	}

	// CommandResponse is the reply to an IPMI command.
	CommandResponse struct {
		// CompletionCode is 0 on success.
		CompletionCode int
		Data           []byte
	}
)

var authTypes = []struct {
	bit  byte
	name string
}{{0x01, "none"}, {0x02, "md2"}, {0x04, "md5"}, {0x10, "straight"}, {0x20, "oem"}}

// Ping reports whether the host answers an RMCP presence ping and advertises
// IPMI support.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const isIPMI = ipmi.Ping('acme.com', 623);
// log(isIPMI);
// ```
func Ping(ctx context.Context, host string, port int) (bool, error) {
	s, err := dial(ctx, host, port)
	if err != nil {
		return false, err
	}
	defer s.close()
	return s.ping()
}

// GetAuthCapabilities returns the authentication capabilities the BMC
// advertises on the current channel.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const caps = ipmi.GetAuthCapabilities('acme.com', 623);
// log(caps.AnonymousLogin);
// ```
func GetAuthCapabilities(ctx context.Context, host string, port int) (*AuthCapabilities, error) {
	s, err := dial(ctx, host, port)
	if err != nil {
		return nil, err
	}
	defer s.close()

	// bit 7 asks for the IPMI 2.0 extended data; an IPMI 1.5 only BMC
	// rejects it, so ask again without
	data, err := s.command(cmdGetChannelAuthCaps, []byte{0x80 | currentChannel, privAdmin})
	if err != nil {
		if data, err = s.command(cmdGetChannelAuthCaps, []byte{currentChannel, privAdmin}); err != nil {
			return nil, err
		}
	}
	return parseAuthCapabilities(data)
}

// parseAuthCapabilities decodes the Get Channel Authentication Capabilities
// response data (IPMI v2.0 table 22-15).
func parseAuthCapabilities(data []byte) (*AuthCapabilities, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("short channel authentication capabilities response")
	}
	caps := &AuthCapabilities{
		IPMI20:           data[1]&0x80 != 0 && data[3]&0x02 != 0,
		AnonymousLogin:   data[2]&0x01 != 0,
		NullUsernames:    data[2]&0x02 != 0,
		NonNullUsernames: data[2]&0x04 != 0,
		UserLevelAuth:    data[2]&0x08 == 0,
		PerMessageAuth:   data[2]&0x10 == 0,
		OEMID:            int(data[4]) | int(data[5])<<8 | int(data[6])<<16,
	}
	for _, authType := range authTypes {
		if data[1]&authType.bit != 0 {
			caps.AuthTypes = append(caps.AuthTypes, authType.name)
		}
	}
	return caps, nil
}

// GetSystemGUID returns the BMC system GUID, which vendors derive from
// serial numbers or MAC addresses.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const guid = ipmi.GetSystemGUID('acme.com', 623);
// log(guid);
// ```
func GetSystemGUID(ctx context.Context, host string, port int) (string, error) {
	s, err := dial(ctx, host, port)
	if err != nil {
		return "", err
	}
	defer s.close()

	data, err := s.command(cmdGetSystemGUID, nil)
	if err != nil {
		return "", err
	}
	if len(data) < 16 {
		return "", fmt.Errorf("short system guid response")
	}
	return hex.EncodeToString(data[:16]), nil
}

// GetCipherSuites returns the IDs of the RMCP+ cipher suites the BMC
// offers. Cipher suite 0 authenticates nothing, so any password logs in.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const suites = ipmi.GetCipherSuites('acme.com', 623);
// log(suites.includes(0));
// ```
func GetCipherSuites(ctx context.Context, host string, port int) ([]int, error) {
	s, err := dial(ctx, host, port)
	if err != nil {
		return nil, err
	}
	defer s.close()

	// the records come in pages of 16 bytes; a shorter page is the last
	var records []byte
	for index := byte(0); index < 64; index++ {
		data, err := s.command(cmdGetCipherSuites, []byte{currentChannel, 0x00, 0x80 | index})
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			records = append(records, data[1:]...)
		}
		if len(data) < 17 {
			break
		}
	}

	return parseCipherSuites(records), nil
}

// parseCipherSuites returns the suite IDs in Get Channel Cipher Suites
// record data. A record starts with 0xc0 (standard) or 0xc1 (oem, followed
// by a 3 byte IANA); algorithm bytes are tagged below 0xc0, so they never
// look like a record start.
func parseCipherSuites(records []byte) []int {
	suites := []int{}
	for i := 0; i < len(records); i++ {
		switch records[i] {
		case 0xc0:
			if i+1 < len(records) {
				suites = append(suites, int(records[i+1]))
				i++
			}
		case 0xc1:
			if i+1 < len(records) {
				suites = append(suites, int(records[i+1]))
				i += 4
			}
		}
	}
	return suites
}

// GetRAKPHash starts an RMCP+ session as username and returns the HMAC the
// BMC answers with. The session is never completed, so no login is
// attempted; the BMC drops the half-open session after its timeout. It fails
// when the BMC rejects the username.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
// log(ipmi.CheckRAKPPassword(hash, 'ADMIN'));
// ```
func GetRAKPHash(ctx context.Context, host string, port int, username string) (*RAKPHash, error) {
	s, err := dial(ctx, host, port)
	if err != nil {
		return nil, err
	}
	defer s.close()

	// the session is never completed, so no login is attempted; md5 is for
	// BMCs that refuse sha1
	var h *handshake
	for _, auth := range []byte{authHMACSHA1, authHMACMD5} {
		if h, err = s.startSession(algorithms{auth: auth}, username, privAdmin); err == nil {
			break
		}
		var refused *rakpError
		if !errors.As(err, &refused) || refused.step != "the session" {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	hash := &RAKPHash{Username: username, Algorithm: "sha1", Salt: hex.EncodeToString(h.rakp2Salt()), HMAC: hex.EncodeToString(h.bmcMAC)}
	if h.auth == authHMACMD5 {
		hash.Algorithm = "md5"
	} else {
		hash.Hashcat = hash.Salt + ":" + hash.HMAC
	}
	return hash, nil
}

// CheckRAKPPassword reports whether password produced hash. It runs offline,
// so it can test any number of passwords without touching the BMC.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
// log(ipmi.CheckRAKPPassword(hash, 'ADMIN'));
// ```
func CheckRAKPPassword(hash *RAKPHash, password string) bool {
	if hash == nil {
		return false
	}
	salt, err := hex.DecodeString(hash.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hash.HMAC)
	if err != nil {
		return false
	}
	newHash := sha1.New
	if hash.Algorithm == "md5" {
		newHash = md5.New
	}
	return hmac.Equal(hmacOf(newHash, []byte(password), salt), want)
}

// FindRAKPPassword returns the first of passwords that produced hash, or an
// empty string.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const hash = ipmi.GetRAKPHash('acme.com', 623, 'root');
// log(ipmi.FindRAKPPassword(hash, ['calvin', 'root', 'admin']));
// ```
func FindRAKPPassword(hash *RAKPHash, passwords []string) string {
	for _, password := range passwords {
		if CheckRAKPPassword(hash, password) {
			return password
		}
	}
	return ""
}

// Login opens an RMCP+ session as username with the given cipher suite
// (0, 1, 2, 3 or 6). Cipher suite 0 skips authentication, so a BMC
// that allows it accepts any password. A rejected login is an error.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const client = new ipmi.Client();
// client.Login('acme.com', 623, 'ADMIN', 'not-the-password', 0);
// ```
func (c *Client) Login(ctx context.Context, host string, port int, username string, password string, cipherSuite int) (bool, error) {
	alg, ok := cipherSuites[cipherSuite]
	if !ok {
		return false, fmt.Errorf("unsupported cipher suite %d", cipherSuite)
	}
	c.Close()
	s, err := dial(ctx, host, port)
	if err != nil {
		return false, err
	}
	h, err := s.startSession(alg, username, privAdmin)
	if err != nil {
		s.close()
		return false, err
	}
	k, err := s.finishSession(h, password)
	if err != nil {
		s.close()
		return false, err
	}
	c.session = &established{session: s, algorithms: alg, keys: k, bmcSessionID: h.bmcSessionID, consoleSessionID: h.consoleSessionID}
	return true, nil
}

// Command sends an IPMI request in the session, such as Get Device ID
// (netFn 0x06, cmd 0x01) or Set Session Privilege Level (0x06, 0x3b).
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const client = new ipmi.Client();
// client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
// const admin = client.Command(0x06, 0x3b, [0x04]).CompletionCode == 0;
// client.Close();
// ```
func (c *Client) Command(netFn int, cmd int, data []byte) (*CommandResponse, error) {
	if c.session == nil {
		return nil, fmt.Errorf("not logged in")
	}
	code, reply, err := c.session.command(byte(netFn), byte(cmd), data)
	if err != nil {
		return nil, err
	}
	return &CommandResponse{CompletionCode: int(code), Data: reply}, nil
}

// Close ends the session on the BMC, freeing its slot.
// @example
// ```javascript
// const ipmi = require('nuclei/ipmi');
// const client = new ipmi.Client();
// client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
// client.Close();
// ```
func (c *Client) Close() {
	if c.session == nil {
		return
	}
	_, _, _ = c.session.command(netFnApp, cmdCloseSession, c.session.bmcSessionID)
	c.session.close()
	c.session = nil
}
