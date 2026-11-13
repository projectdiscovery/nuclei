package vnc

// Tests that the network policy is enforced by isVNC before any connection.

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestIsVNCDeniesExcludedHost verifies that isVNC rejects a host that appears
// in the --exclude-hosts list.
func TestIsVNCDeniesExcludedHost(t *testing.T) {
	execID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.50"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck
	_, err := isVNC(ctx, execID, "203.0.113.50", 5900)
	require.Error(t, err, "isVNC must reject a host excluded by network policy")
	errStr := err.Error()
	require.True(t,
		containsAny(errStr, "denied", "dropped", "not allowed", "excluded"),
		"error %q should indicate a network-policy denial", errStr)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
