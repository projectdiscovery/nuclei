package goexec

import (
	"encoding/json"
	"testing"
)

func TestAuthValidationModes(t *testing.T) {
	tests := []struct {
		name    string
		auth    *Auth
		wantErr bool
	}{
		{name: "password", auth: Password("CORP\\auditor", "secret")},
		{name: "nt hash", auth: NTHash("CORP\\auditor", "31d6cfe0d16ae931b73c59d7e0c089c0")},
		{name: "kerberos password", auth: Kerberos("auditor@CORP.LOCAL", map[string]interface{}{"password": "secret"})},
		{name: "aes", auth: AESKey("auditor@CORP.LOCAL", "00112233445566778899aabbccddeeff")},
		{name: "ccache", auth: CCache("/tmp/krb5cc_1000")},
		{name: "pfx", auth: PFX("CORP\\auditor", "/tmp/client.pfx", "secret")},
		{name: "missing auth", auth: &Auth{}, wantErr: true},
		{name: "missing username", auth: Password("", "secret"), wantErr: true},
		{name: "multiple non kerberos", auth: &Auth{username: "u", password: "p", ntHash: "h"}, wantErr: true},
		{name: "multiple kerberos options", auth: Kerberos("auditor@CORP.LOCAL", map[string]interface{}{"password": "p", "ntHash": "h"}), wantErr: true},
		{name: "aes plus password", auth: AESKey("auditor@CORP.LOCAL", "00112233445566778899aabbccddeeff", map[string]interface{}{"password": "p"}), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auth.validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestAuthJSONDoesNotExposeSecrets(t *testing.T) {
	auth := Password("CORP\\auditor", "super-secret")
	data, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Fatalf("expected empty auth JSON, got %s", data)
	}
}
