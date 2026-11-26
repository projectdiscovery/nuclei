package pop3

// Tests that the network policy (IsHostAllowed + fastdialer deny) is enforced
// by isPoP3 before any successful connection is established to a denied host.

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestIsPOP3DeniesExcludedHost verifies that isPoP3 returns an error when the
// target host is in the --exclude-hosts list.  The network-policy enforcement
// happens either via IsHostAllowed (hostname form) or via the fastdialer's own
// IP-level deny check; either way the call must not succeed.
func TestIsPOP3DeniesExcludedHost(t *testing.T) {
	execID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.50"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck
	_, err := isPoP3(ctx, execID, "203.0.113.50", 110)
	require.Error(t, err, "isPoP3 must reject a host excluded by network policy")
	// The error may come from IsHostAllowed (hostname form) or from the
	// fastdialer IP-level deny; either contains "denied" or "dropped".
	errStr := err.Error()
	require.True(t,
		containsAny(errStr, "denied", "dropped", "not allowed", "excluded"),
		"error %q should indicate a network-policy denial", errStr)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
