//go:build integration
// +build integration

package integration_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// javascriptASRepRoast exercises templates/ad/asrep-roast.yaml end-to-end
// against a pure-Go mock KDC. The template iterates a list of usernames; the
// mock KDC returns a valid AS-REP only for the roastable user and a KRB-ERROR
// for the rest, mirroring how a real Active Directory DC behaves.
type javascriptASRepRoast struct{}

const (
	mockKDCRealm         = "ACME.LOCAL"
	mockKDCRoastableUser = "svc-roast"
	// mockKDCASREPCipherHex is a deterministic 64-byte cipher embedded in the
	// AS-REP. The first 16 bytes (32 hex chars) become the hashcat checksum
	// and the remaining 48 bytes become the data section, producing a stable
	// $krb5asrep$ string we can match exactly.
	mockKDCASREPCipherHex = "deadbeefcafebabefeedfacef00dd00dbaadc0debaadc0debaadc0debaadc0deabad1deaabad1deaabad1deaabad1deabad1deaabad1deaabad1deaabad1deaa"
)

func (j *javascriptASRepRoast) Execute(filePath string) error {
	kdc, err := newMockKDC()
	if err != nil {
		return fmt.Errorf("could not start mock KDC: %w", err)
	}
	defer kdc.Close()

	results, err := runSignedNucleiTemplateAndGetResults(filePath, kdc.Address(), debug)
	if err != nil {
		return err
	}
	if err := expectResultsCount(results, 1); err != nil {
		return err
	}

	expected := fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s",
		mockKDCRoastableUser, mockKDCRealm,
		mockKDCASREPCipherHex[:32], mockKDCASREPCipherHex[32:])
	for _, r := range results {
		if strings.Contains(r, expected) {
			return nil
		}
	}
	return fmt.Errorf("expected $krb5asrep$ hash %q in results, got %v", expected, results)
}

// mockKDC is a minimal Kerberos KDC that speaks just enough of RFC 4120 over
// TCP to satisfy the AS-REP roasting flow: read a length-prefixed AS-REQ,
// extract the client principal name, and either reply with a valid AS-REP
// (deterministic cipher) or with a KRB-ERROR. Used for integration testing
// templates/ad/asrep-roast.yaml without requiring a real Active Directory DC.
type mockKDC struct {
	listener net.Listener
	closed   atomic.Bool
}

func newMockKDC() (*mockKDC, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	k := &mockKDC{listener: l}
	go k.serve()
	return k, nil
}

func (k *mockKDC) Address() string { return k.listener.Addr().String() }

func (k *mockKDC) Close() {
	if k.closed.Swap(true) {
		return
	}
	_ = k.listener.Close()
}

func (k *mockKDC) serve() {
	for {
		conn, err := k.listener.Accept()
		if err != nil {
			if k.closed.Load() {
				return
			}
			continue
		}
		go k.handle(conn)
	}
}

func (k *mockKDC) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	bodyLen := binary.BigEndian.Uint32(hdr)
	if bodyLen == 0 || bodyLen > 1<<20 {
		return
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	username, ok := asReqUsername(body)
	if !ok {
		writeKRBError(conn, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN)
		return
	}

	if username != mockKDCRoastableUser {
		// Mirror a real DC: unknown principals -> C_PRINCIPAL_UNKNOWN, known
		// principals that require pre-auth -> KDC_ERR_PREAUTH_REQUIRED.
		if username == "krbtgt" {
			writeKRBError(conn, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN)
		} else {
			writeKRBError(conn, errorcode.KDC_ERR_PREAUTH_REQUIRED)
		}
		return
	}

	rep, err := buildMockASREP(mockKDCRealm, mockKDCRoastableUser, mustHex(mockKDCASREPCipherHex))
	if err != nil {
		writeKRBError(conn, errorcode.KDC_ERR_NONE)
		return
	}
	writeFramed(conn, rep)
}

// asReqUsername decodes just enough of the AS-REQ to pull out the first
// component of the client principal name. Returns ("", false) if the request
// does not parse as an AS-REQ or has no cname.
func asReqUsername(body []byte) (string, bool) {
	var req messages.ASReq
	if err := req.Unmarshal(body); err != nil {
		return "", false
	}
	if len(req.ReqBody.CName.NameString) == 0 {
		return "", false
	}
	return req.ReqBody.CName.NameString[0], true
}

func writeFramed(conn net.Conn, payload []byte) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	_, _ = conn.Write(append(hdr, payload...))
}

func writeKRBError(conn net.Conn, code int32) {
	now := time.Now().UTC()
	e := messages.KRBError{
		PVNO:      iana.PVNO,
		MsgType:   msgtype.KRB_ERROR,
		STime:     now,
		Susec:     int((now.UnixNano() / int64(time.Microsecond)) - (now.Unix() * 1e6)),
		ErrorCode: code,
		Realm:     mockKDCRealm,
		SName:     types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+mockKDCRealm),
	}
	b, err := e.Marshal()
	if err != nil {
		return
	}
	writeFramed(conn, b)
}

// buildMockASREP constructs a syntactically valid AS-REP whose outer enc-part
// uses RC4-HMAC (etype 23) with the supplied cipher, which is what
// goimpacket.GetASREPWithDialer parses to format the $krb5asrep$ hash.
// The embedded ticket is structurally valid but its inner cipher is an opaque
// blob since the client never tries to decrypt it.
func buildMockASREP(realm, user string, cipher []byte) ([]byte, error) {
	tkt := messages.Ticket{
		TktVNO: iana.PVNO,
		Realm:  realm,
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm),
		EncPart: types.EncryptedData{
			EType:  23,
			Cipher: bytes.Repeat([]byte{0xaa}, 32),
		},
	}
	rep := messages.ASRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_AS_REP,
			CRealm:  realm,
			CName:   types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user),
			Ticket:  tkt,
			EncPart: types.EncryptedData{EType: 23, Cipher: cipher},
		},
	}
	return rep.Marshal()
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		hi = hexNibble(s[i*2])
		lo = hexNibble(s[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
