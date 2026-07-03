package goexec

import (
	"errors"
	"strings"
	"testing"
)

func TestRedactorRemovesCredentialMaterial(t *testing.T) {
	auth := &Auth{
		username:    "CORP\\auditor",
		password:    "secret-pass",
		ntHash:      "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
		aesKey:      "00112233445566778899aabbccddeeff",
		pfxPassword: "pfx-secret",
		ccache:      "/tmp/krb5cc_secret",
	}
	redactor := newRedactor(auth)
	got := redactor.Error(errors.New("secret-pass 31d6cfe0d16ae931b73c59d7e0c089c0 00112233445566778899aabbccddeeff pfx-secret /tmp/krb5cc_secret"))
	for _, secret := range []string{"secret-pass", "31d6cfe0d16ae931b73c59d7e0c089c0", "00112233445566778899aabbccddeeff", "pfx-secret", "/tmp/krb5cc_secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q was not redacted from %q", secret, got)
		}
	}
}
