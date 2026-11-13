package kerberos

import (
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// buildTicketWithCipher creates a messages.Ticket whose EncPart.Cipher has the
// given length. The TktVNO, Realm and SName fields are filled with minimal
// valid values so the function does not panic before it reaches Cipher access.
func buildTicketWithCipher(cipherLen int) messages.Ticket {
	cipher := make([]byte, cipherLen)
	for i := range cipher {
		cipher[i] = byte(i & 0xff)
	}
	return messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.REALM",
		SName: types.PrincipalName{
			NameType:   1,
			NameString: []string{"host", "server.test.realm"},
		},
		EncPart: types.EncryptedData{
			EType:  17,
			Cipher: cipher,
		},
	}
}

// buildASRepWithCipher creates a messages.ASRep whose EncPart.Cipher has the
// given length.
func buildASRepWithCipher(cipherLen int) messages.ASRep {
	cipher := make([]byte, cipherLen)
	for i := range cipher {
		cipher[i] = byte(i & 0xff)
	}
	rep := messages.ASRep{}
	rep.EncPart = types.EncryptedData{
		EType:  17,
		Cipher: cipher,
	}
	rep.CName = types.PrincipalName{
		NameType:   1,
		NameString: []string{"testuser"},
	}
	rep.CRealm = "TEST.REALM"
	return rep
}

// --- TGStoHashcat ---

// TestTGStoHashcat_NoPanicOnShortCipher is the regression test.
// Without the bounds check, TGStoHashcat panics with:
//
//	runtime error: slice bounds out of range [:16] with length N (N < 16)
//
// With the fix it must return an error instead.
func TestTGStoHashcat_NoPanicOnShortCipher(t *testing.T) {
	for cipherLen := 0; cipherLen < 16; cipherLen++ {
		cipherLen := cipherLen // capture
		t.Run("", func(t *testing.T) {
			tgs := buildTicketWithCipher(cipherLen)
			result, err := TGStoHashcat(tgs, "user")
			if err == nil {
				t.Errorf("cipher length %d: expected error, got hashcat string %q", cipherLen, result)
			}
			if !strings.Contains(err.Error(), "too short") {
				t.Errorf("cipher length %d: unexpected error message %q", cipherLen, err.Error())
			}
		})
	}
}

// TestTGStoHashcat_Valid_16Bytes confirms that a cipher of exactly 16 bytes succeeds.
func TestTGStoHashcat_Valid_16Bytes(t *testing.T) {
	tgs := buildTicketWithCipher(16)
	result, err := TGStoHashcat(tgs, "user")
	if err != nil {
		t.Fatalf("unexpected error for 16-byte cipher: %v", err)
	}
	if !strings.HasPrefix(result, "$krb5tgs$") {
		t.Errorf("unexpected hash format: %q", result)
	}
}

// TestTGStoHashcat_Valid_Large confirms that a larger cipher also succeeds.
func TestTGStoHashcat_Valid_Large(t *testing.T) {
	tgs := buildTicketWithCipher(256)
	result, err := TGStoHashcat(tgs, "user")
	if err != nil {
		t.Fatalf("unexpected error for 256-byte cipher: %v", err)
	}
	if !strings.HasPrefix(result, "$krb5tgs$") {
		t.Errorf("unexpected hash format: %q", result)
	}
}

// --- ASRepToHashcat ---

// TestASRepToHashcat_NoPanicOnShortCipher is the regression test for ASRep.
func TestASRepToHashcat_NoPanicOnShortCipher(t *testing.T) {
	for cipherLen := 0; cipherLen < 16; cipherLen++ {
		cipherLen := cipherLen
		t.Run("", func(t *testing.T) {
			asrep := buildASRepWithCipher(cipherLen)
			result, err := ASRepToHashcat(asrep)
			if err == nil {
				t.Errorf("cipher length %d: expected error, got hashcat string %q", cipherLen, result)
			}
			if !strings.Contains(err.Error(), "too short") {
				t.Errorf("cipher length %d: unexpected error message %q", cipherLen, err.Error())
			}
		})
	}
}

// TestASRepToHashcat_Valid_16Bytes confirms that a cipher of exactly 16 bytes succeeds.
func TestASRepToHashcat_Valid_16Bytes(t *testing.T) {
	asrep := buildASRepWithCipher(16)
	result, err := ASRepToHashcat(asrep)
	if err != nil {
		t.Fatalf("unexpected error for 16-byte cipher: %v", err)
	}
	if !strings.HasPrefix(result, "$krb5asrep$") {
		t.Errorf("unexpected hash format: %q", result)
	}
}
