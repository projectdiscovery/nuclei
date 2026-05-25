package telnetmini

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildChallenge constructs a minimal NTLM type-2 challenge message of exactly
// headerLen bytes, wrapped in the telnet framing expected by ParseNTLMResponse.
func buildChallenge(headerLen int) []byte {
	ntlm := make([]byte, headerLen)

	copy(ntlm[0:], "NTLMSSP\x00")

	if headerLen >= 12 {
		binary.LittleEndian.PutUint32(ntlm[8:12], 2)
	}

	var out []byte
	out = append(out, ntlm...)
	out = append(out, 0xFF, 0xF0)
	return out
}

// buildValidChallenge returns a fully-formed 48-byte NTLM type-2 challenge with
// a small UTF-16LE target name appended after the fixed header.
func buildValidChallenge() []byte {
	targetName := []byte("W\x00I\x00N\x00") // "WIN" in UTF-16LE
	ntlm := make([]byte, 48+len(targetName))

	copy(ntlm[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], 2)

	binary.LittleEndian.PutUint16(ntlm[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(ntlm[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(ntlm[16:20], 48)

	binary.LittleEndian.PutUint16(ntlm[40:42], 0)
	binary.LittleEndian.PutUint32(ntlm[44:48], 48)

	copy(ntlm[48:], targetName)

	var out []byte
	out = append(out, ntlm...)
	out = append(out, 0xFF, 0xF0)
	return out
}

func TestParseNTLMResponse_Valid(t *testing.T) {
	data := buildValidChallenge()
	resp, err := ParseNTLMResponse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestParseNTLMResponse_Minimal48Bytes verifies that a challenge with exactly
// 48 bytes (the minimum valid fixed-header size, no target name or info) is
// accepted — confirming the boundary condition of the len<48 guard.
func TestParseNTLMResponse_Minimal48Bytes(t *testing.T) {
	data := buildChallenge(48)
	resp, err := ParseNTLMResponse(data)
	if err != nil {
		t.Fatalf("48-byte challenge should be valid, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response for 48-byte challenge")
	}
}

func TestParseNTLMResponse_ErrorCases(t *testing.T) {
	wrongTypeChallenge := buildChallenge(48)
	binary.LittleEndian.PutUint32(wrongTypeChallenge[8:12], 1)

	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: "NTLMSSP signature not found",
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: "NTLMSSP signature not found",
		},
		{
			name:    "missing NTLMSSP signature",
			input:   []byte("hello world\xFF\xF0"),
			wantErr: "NTLMSSP signature not found",
		},
		{
			name:    "missing Sub-option End terminator",
			input:   []byte("NTLMSSP\x00" + strings.Repeat("\x00", 40)),
			wantErr: "not properly terminated",
		},
		{
			name:    "wrong message type",
			input:   wrongTypeChallenge,
			wantErr: "expected NTLM challenge message",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNTLMResponse(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestParseNTLMResponse_TruncatedNoPanic verifies that every NTLM section length
// in [12, 47] returns an error instead of panicking (regression for slice-bounds bug).
func TestParseNTLMResponse_TruncatedNoPanic(t *testing.T) {
	for length := 12; length < 48; length++ {
		data := buildChallenge(length)
		_, err := ParseNTLMResponse(data)
		if err == nil {
			t.Errorf("length %d: expected error for truncated challenge, got nil", length)
		}
	}
}
