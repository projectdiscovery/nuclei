package rdp

// Tests that IsHostAllowed is enforced by IsRDP, CheckRDPAuth and
// CheckRDPEncryption before any network dial is attempted.

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func setupPolicy(t *testing.T, excludedHosts ...string) string {
	t.Helper()
	execID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: excludedHosts,
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	return execID
}

func ctxWithExec(execID string) context.Context {
	return context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck
}

// TestIsRDPDeniesExcludedHost verifies that isRDP returns an error when the
// target host is in the --exclude-hosts list.
func TestIsRDPDeniesExcludedHost(t *testing.T) {
	execID := setupPolicy(t, "203.0.113.50")
	_, err := isRDP(ctxWithExec(execID), execID, "203.0.113.50", 3389)
	require.Error(t, err, "isRDP must reject a host that is excluded by policy")
	require.Contains(t, err.Error(), "203.0.113.50")
}

// TestCheckRDPAuthDeniesExcludedHost verifies that checkRDPAuth respects policy.
func TestCheckRDPAuthDeniesExcludedHost(t *testing.T) {
	execID := setupPolicy(t, "203.0.113.50")
	_, err := checkRDPAuth(ctxWithExec(execID), execID, "203.0.113.50", 3389)
	require.Error(t, err, "checkRDPAuth must reject a host that is excluded by policy")
	require.Contains(t, err.Error(), "203.0.113.50")
}

// TestCheckRDPEncryptionDeniesExcludedHost verifies that checkRDPEncryption
// respects policy before attempting any network connection.
func TestCheckRDPEncryptionDeniesExcludedHost(t *testing.T) {
	execID := setupPolicy(t, "203.0.113.50")
	_, err := checkRDPEncryption(ctxWithExec(execID), execID, "203.0.113.50", 3389)
	require.Error(t, err, "checkRDPEncryption must reject a host that is excluded by policy")
	require.Contains(t, err.Error(), "203.0.113.50")
}
