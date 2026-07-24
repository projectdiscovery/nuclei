package smb

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDecodeNTLMHashBareNT(t *testing.T) {
	// 16 zero bytes as hex
	raw := "00000000000000000000000000000000"
	got, err := decodeNTLMHash(raw)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 16), got)
}

func TestDecodeNTLMHashLMColonNT(t *testing.T) {
	nt := "31d6cfe0d16ae931b73c59d7e0c089c0"
	raw := "aad3b435b51404eeaad3b435b51404ee:" + nt
	got, err := decodeNTLMHash(raw)
	require.NoError(t, err)
	want, err := hex.DecodeString(nt)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDecodeNTLMHashInvalidHex(t *testing.T) {
	_, err := decodeNTLMHash("not-hex")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ntlm hash")
}

func TestDecodeNTLMHashWrongLength(t *testing.T) {
	_, err := decodeNTLMHash("aabbcc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ntlm hash length")
}

func TestListSharesWithOptionsRejectsInvalidHostPort(t *testing.T) {
	_, err := listSharesWithOptions(t.Context(), "exec", SMBOptions{Host: "", Port: 445})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid host or port")

	_, err = listSharesWithOptions(t.Context(), "exec", SMBOptions{Host: "acme.com", Port: 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid host or port")
}

func TestListSharesWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	_, err := listSharesWithOptions(context.Background(), executionID, SMBOptions{
		Host: "127.0.0.1", Port: 445, Domain: "ACME", Timeout: 1,
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "network policy") && strings.Contains(err.Error(), "127.0.0.1"))
}

func TestSMBOptionsFieldsAreWiredForInitiator(t *testing.T) {
	opts := SMBOptions{
		Host:        "dc.acme.com",
		Port:        445,
		User:        "Administrator",
		Password:    "secret",
		Hash:        "31d6cfe0d16ae931b73c59d7e0c089c0",
		Domain:      "ACME",
		Workstation: "WS01",
		TargetSPN:   "cifs/dc.acme.com",
		Timeout:     15,
	}
	require.Equal(t, "ACME", opts.Domain)
	require.Equal(t, "WS01", opts.Workstation)
	require.Equal(t, "cifs/dc.acme.com", opts.TargetSPN)
	require.Equal(t, 15, opts.Timeout)

	hash, err := decodeNTLMHash(opts.Hash)
	require.NoError(t, err)
	require.Len(t, hash, 16)
}
