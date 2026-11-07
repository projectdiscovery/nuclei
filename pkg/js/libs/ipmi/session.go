package ipmi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// RMCP+ algorithm numbers (IPMI v2.0 tables 13-17 to 13-19).
const (
	authNone     = 0x00
	authHMACSHA1 = 0x01
	authHMACMD5  = 0x02

	integrityNone       = 0x00
	integrityHMACSHA196 = 0x01

	confidentialityNone      = 0x00
	confidentialityAESCBC128 = 0x01

	payloadIPMI      = 0x00
	payloadEncrypted = 0x80
	payloadSigned    = 0x40

	cmdCloseSession = 0x3c

	// rakp status codes worth naming in errors
	rakpInvalidRole      = 0x09
	rakpUnauthorizedName = 0x0d
)

type algorithms struct {
	auth, integrity, confidentiality byte
}

// cipherSuites lists the suites a session can be opened with. Suites with
// SHA-256 or MD5 message integrity are left out until they can be checked
// against a BMC that implements them correctly.
var cipherSuites = map[int]algorithms{
	0: {authNone, integrityNone, confidentialityNone},
	1: {authHMACSHA1, integrityNone, confidentialityNone},
	2: {authHMACSHA1, integrityHMACSHA196, confidentialityNone},
	3: {authHMACSHA1, integrityHMACSHA196, confidentialityAESCBC128},
	6: {authHMACMD5, integrityNone, confidentialityNone},
}

func authHash(auth byte) func() hash.Hash {
	switch auth {
	case authHMACSHA1:
		return sha1.New
	case authHMACMD5:
		return md5.New
	}
	return nil
}

func hmacOf(newHash func() hash.Hash, key []byte, parts ...[]byte) []byte {
	mac := hmac.New(newHash, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

// handshake is the state of an RMCP+ session setup up to RAKP message 2.
type handshake struct {
	algorithms
	consoleSessionID, bmcSessionID []byte
	consoleRandom, bmcRandom       []byte
	bmcGUID                        []byte
	role                           byte
	username                       string
	// bmcMAC is the RAKP message 2 key exchange code, empty without
	// authentication.
	bmcMAC []byte
}

// rakpError is a non-zero status in an RMCP+ session setup reply.
type rakpError struct {
	step   string
	status byte
}

func (e *rakpError) Error() string {
	switch e.status {
	case rakpUnauthorizedName:
		return fmt.Sprintf("bmc rejected the username in %s (status 0x%02x)", e.step, e.status)
	case rakpInvalidRole:
		return fmt.Sprintf("bmc rejected the requested privilege in %s (status 0x%02x)", e.step, e.status)
	}
	return fmt.Sprintf("bmc refused %s with status 0x%02x", e.step, e.status)
}

// startSession opens an RMCP+ session and runs RAKP messages 1 and 2.
func (s *session) startSession(alg algorithms, username string, privilege byte) (*handshake, error) {
	if len(username) > 16 {
		return nil, fmt.Errorf("ipmi usernames are at most 16 bytes")
	}
	h := &handshake{
		algorithms:       alg,
		consoleSessionID: make([]byte, 4),
		consoleRandom:    make([]byte, 16),
		role:             privilege | rakpNameOnlyLookup,
		username:         username,
	}
	if _, err := rand.Read(h.consoleSessionID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(h.consoleRandom); err != nil {
		return nil, err
	}

	open := []byte{0x00, privilege, 0x00, 0x00}
	open = append(open, h.consoleSessionID...)
	open = append(open,
		0x00, 0x00, 0x00, 0x08, alg.auth, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x08, alg.integrity, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x08, alg.confidentiality, 0x00, 0x00, 0x00,
	)
	opened, err := s.rmcpPlus(payloadOpenSessionRequest, open, payloadOpenSessionResponse)
	if err != nil {
		return nil, err
	}
	if len(opened) < 2 {
		return nil, fmt.Errorf("short open session response")
	}
	if opened[1] != 0 {
		return nil, &rakpError{step: "the session", status: opened[1]}
	}
	if len(opened) < 12 {
		return nil, fmt.Errorf("short open session response")
	}
	h.bmcSessionID = bytes.Clone(opened[8:12])

	rakp1 := []byte{0x00, 0x00, 0x00, 0x00}
	rakp1 = append(rakp1, h.bmcSessionID...)
	rakp1 = append(rakp1, h.consoleRandom...)
	rakp1 = append(rakp1, h.role, 0x00, 0x00, byte(len(username)))
	rakp1 = append(rakp1, username...)
	rakp2, err := s.rmcpPlus(payloadRAKP1, rakp1, payloadRAKP2)
	if err != nil {
		return nil, err
	}
	if len(rakp2) < 2 {
		return nil, fmt.Errorf("short rakp message 2")
	}
	if rakp2[1] != 0 {
		return nil, &rakpError{step: "rakp message 1", status: rakp2[1]}
	}
	if len(rakp2) < 40 {
		return nil, fmt.Errorf("short rakp message 2")
	}
	h.bmcRandom = bytes.Clone(rakp2[8:24])
	h.bmcGUID = bytes.Clone(rakp2[24:40])
	h.bmcMAC = bytes.Clone(rakp2[40:])
	return h, nil
}

// rakp2Salt is everything the RAKP message 2 code covers.
func (h *handshake) rakp2Salt() []byte {
	salt := make([]byte, 0, 58+len(h.username))
	salt = append(salt, h.consoleSessionID...)
	salt = append(salt, h.bmcSessionID...)
	salt = append(salt, h.consoleRandom...)
	salt = append(salt, h.bmcRandom...)
	salt = append(salt, h.bmcGUID...)
	salt = append(salt, h.role, byte(len(h.username)))
	return append(salt, h.username...)
}

// keys are the session keys derived from the session integrity key.
type keys struct {
	integrity []byte // K1
	aes       []byte // first 16 bytes of K2
}

// finishSession runs RAKP messages 3 and 4, which is where a wrong password
// is rejected, and derives the session keys. Both directions are proven:
// the BMC's RAKP message 2 code and RAKP message 4 integrity value must
// match the password, so a peer that only answers with success statuses
// cannot pass for a login.
func (s *session) finishSession(h *handshake, password string) (*keys, error) {
	if len(password) > 20 {
		return nil, fmt.Errorf("ipmi passwords are at most 20 bytes")
	}
	newHash := authHash(h.auth)
	if newHash != nil && !hmac.Equal(h.bmcMAC, hmacOf(newHash, []byte(password), h.rakp2Salt())) {
		return nil, errBMCProof
	}

	rakp3 := []byte{0x00, 0x00, 0x00, 0x00}
	rakp3 = append(rakp3, h.bmcSessionID...)
	if newHash != nil {
		rakp3 = append(rakp3, hmacOf(newHash, []byte(password),
			h.bmcRandom, h.consoleSessionID, []byte{h.role, byte(len(h.username))}, []byte(h.username))...)
	}
	rakp4, err := s.rmcpPlus(payloadRAKP3, rakp3, payloadRAKP4)
	if err != nil {
		return nil, err
	}
	if len(rakp4) < 2 {
		return nil, fmt.Errorf("short rakp message 4")
	}
	if rakp4[1] != 0 {
		return nil, &rakpError{step: "the login", status: rakp4[1]}
	}
	if newHash == nil {
		return &keys{}, nil
	}

	sik := hmacOf(newHash, []byte(password),
		h.consoleRandom, h.bmcRandom, []byte{h.role, byte(len(h.username))}, []byte(h.username))
	if !rakp4Valid(newHash, sik, h, rakp4) {
		return nil, errBMCProof
	}
	return &keys{
		integrity: hmacOf(newHash, sik, bytes.Repeat([]byte{0x01}, 20)),
		aes:       hmacOf(newHash, sik, bytes.Repeat([]byte{0x02}, 20))[:16],
	}, nil
}

// errBMCProof means the peer's authentication code does not match the
// password: a wrong password, or something other than the BMC answering.
var errBMCProof = errors.New("bmc authentication code does not match the password")

// rakp4Valid checks the RAKP message 4 integrity value, the session key's
// HMAC over the console random, BMC session ID and BMC GUID, truncated to
// 12 bytes for sha1 and 16 for md5.
func rakp4Valid(newHash func() hash.Hash, sik []byte, h *handshake, rakp4 []byte) bool {
	size := 12
	if h.auth == authHMACMD5 {
		size = 16
	}
	if len(rakp4) < 8+size {
		return false
	}
	want := hmacOf(newHash, sik, h.consoleRandom, h.bmcSessionID, h.bmcGUID)[:size]
	return hmac.Equal(rakp4[8:8+size], want)
}

// established is an authenticated RMCP+ session.
type established struct {
	*session
	algorithms
	keys             *keys
	bmcSessionID     []byte
	consoleSessionID []byte
	sequence         uint32
	requestSeq       byte
}

// command sends an IPMI request inside the session and returns its
// completion code and response data.
func (e *established) command(netFn, cmd byte, data []byte) (byte, []byte, error) {
	// the request sequence is 6 bits on the wire
	e.requestSeq = (e.requestSeq + 1) & 0x3f
	header := []byte{bmcAddress, netFn << 2}
	body := append([]byte{consoleAddress, e.requestSeq << 2, cmd}, data...)
	message := append(append(header, checksum(header)), body...)
	message = append(message, checksum(body))

	payloadType := byte(payloadIPMI)
	if e.confidentiality == confidentialityAESCBC128 {
		payloadType |= payloadEncrypted
		var err error
		if message, err = encryptPayload(e.keys.aes, message); err != nil {
			return 0, nil, err
		}
	}
	if e.integrity != integrityNone {
		payloadType |= payloadSigned
	}

	e.sequence++
	packet := append(rmcpHeader(rmcpClassIPMI), authTypeRMCPP, payloadType)
	packet = append(packet, e.bmcSessionID...)
	packet = binary.LittleEndian.AppendUint32(packet, e.sequence)
	packet = binary.LittleEndian.AppendUint16(packet, uint16(len(message)))
	packet = append(packet, message...)
	if e.integrity != integrityNone {
		packet = e.sign(packet)
	}

	// a reply must be for this session, pass the integrity check when the
	// session is signed, and answer this request, not an earlier one that
	// arrived late
	var payload []byte
	_, err := e.exchange(packet, func(reply []byte) bool {
		payload = e.open(reply)
		return len(payload) >= 8 && payload[4]>>2 == e.requestSeq && payload[5] == cmd
	})
	if err != nil {
		return 0, nil, err
	}
	// rqAddr, netFn, checksum, rsAddr, seq, cmd, completion code, data,
	// checksum
	return payload[6], bytes.Clone(payload[7 : len(payload)-1]), nil
}

// open returns the IPMI message in a session reply, or nil when the reply
// is not for this session or fails its integrity check.
func (e *established) open(reply []byte) []byte {
	if len(reply) < 16 || reply[3] != rmcpClassIPMI || reply[4] != authTypeRMCPP || reply[5]&0x3f != payloadIPMI {
		return nil
	}
	if !bytes.Equal(reply[6:10], e.consoleSessionID) {
		return nil
	}
	length := int(binary.LittleEndian.Uint16(reply[14:16]))
	if len(reply) < 16+length {
		return nil
	}
	if e.integrity != integrityNone {
		if reply[5]&payloadSigned == 0 || !e.verify(reply, 16+length) {
			return nil
		}
	}
	payload := reply[16 : 16+length]
	if reply[5]&payloadEncrypted != 0 {
		var err error
		if payload, err = decryptPayload(e.keys.aes, payload); err != nil {
			return nil
		}
	}
	return payload
}

// verify checks a reply's HMAC-SHA1-96 trailer: the pad after the payload,
// pad length and next header, then the code over everything from the auth
// type on.
func (e *established) verify(reply []byte, payloadEnd int) bool {
	const codeSize = 12
	if len(reply) < payloadEnd+2+codeSize {
		return false
	}
	codeStart := len(reply) - codeSize
	if reply[codeStart-1] != 0x07 || int(reply[codeStart-2]) != codeStart-2-payloadEnd {
		return false
	}
	want := hmacOf(sha1.New, e.keys.integrity, reply[4:codeStart])[:codeSize]
	return hmac.Equal(reply[codeStart:], want)
}

// sign appends the HMAC-SHA1-96 integrity trailer: pad to a multiple of 4 from the auth
// type on, pad length, next header, and the truncated HMAC over it all.
func (e *established) sign(packet []byte) []byte {
	pad := (4 - (len(packet)-4+2)%4) % 4
	packet = append(packet, bytes.Repeat([]byte{0xff}, pad)...)
	packet = append(packet, byte(pad), 0x07)
	return append(packet, hmacOf(sha1.New, e.keys.integrity, packet[4:])[:12]...)
}

// encryptPayload is AES-CBC-128 with a random IV in front and the
// confidentiality pad (1, 2, 3, ... then its length) at the end.
func encryptPayload(key, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := (aes.BlockSize - (len(payload)+1)%aes.BlockSize) % aes.BlockSize
	plain := bytes.Clone(payload)
	for i := 1; i <= pad; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(pad))

	out := make([]byte, aes.BlockSize+len(plain))
	if _, err := rand.Read(out[:aes.BlockSize]); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
	return out, nil
}

func decryptPayload(key, payload []byte) ([]byte, error) {
	if len(payload) < 2*aes.BlockSize || len(payload)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("malformed encrypted payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(payload)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, payload[:aes.BlockSize]).CryptBlocks(plain, payload[aes.BlockSize:])
	pad := int(plain[len(plain)-1])
	if pad+1 > len(plain) {
		return nil, fmt.Errorf("malformed encrypted payload")
	}
	return plain[:len(plain)-pad-1], nil
}
