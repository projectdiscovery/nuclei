package protocolstate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func initTestDialers(t *testing.T, opts *types.Options) context.Context {
	t.Helper()
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if opts.ExecutionId == "" {
		opts.ExecutionId = t.Name()
	}
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	ctx := context.WithValue(context.Background(), "executionId", opts.ExecutionId) //nolint:staticcheck
	return ctx
}

func TestDialAllowedWithExecutionIDRequiresInitializedDialers(t *testing.T) {
	ctx := context.Background()
	_, err := protocolstate.DialAllowedWithExecutionID(ctx, "missing", "tcp", "127.0.0.1:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "dialers not initialized")
}

func TestDialAllowedRejectsExcludedHost(t *testing.T) {
	opts := &types.Options{
		ExecutionId:    "dial-exclude-" + t.Name(),
		ExcludeTargets: []string{"203.0.113.10"},
	}
	ctx := initTestDialers(t, opts)

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := protocolstate.DialAllowed(dialCtx, "tcp", "203.0.113.10:445")
	require.Error(t, err)
}

func TestDialAllowedAllowsNonExcludedHost(t *testing.T) {
	opts := &types.Options{
		ExecutionId:    "dial-allow-" + t.Name(),
		ExcludeTargets: []string{"203.0.113.10"},
	}
	ctx := initTestDialers(t, opts)

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// 127.0.0.1:1 should fail fast with connection refused, not policy denial.
	_, err := protocolstate.DialAllowed(dialCtx, "tcp", "127.0.0.1:1")
	require.Error(t, err)
	require.NotContains(t, strings.ToLower(err.Error()), "network policy")
}

func TestIsHostAllowedFailsClosedWithInitializedDialersButExcludedHost(t *testing.T) {
	opts := &types.Options{
		ExecutionId:    "host-deny-" + t.Name(),
		ExcludeTargets: []string{"203.0.113.10"},
	}
	_ = initTestDialers(t, opts)
	require.False(t, protocolstate.IsHostAllowed(opts.ExecutionId, "203.0.113.10"))
}

func TestIsHostAllowedAllowsNonExcludedHost(t *testing.T) {
	opts := &types.Options{
		ExecutionId:    "host-allow-" + t.Name(),
		ExcludeTargets: []string{"203.0.113.10"},
	}
	_ = initTestDialers(t, opts)
	require.True(t, protocolstate.IsHostAllowed(opts.ExecutionId, "127.0.0.1"))
}

func TestExecutionIDFromContext(t *testing.T) {
	require.Equal(t, "", protocolstate.ExecutionIDFromContext(context.Background()))
	require.Equal(t, "", protocolstate.ExecutionIDFromContext(nil))

	ctx := context.WithValue(context.Background(), "executionId", "abc") //nolint:staticcheck
	require.Equal(t, "abc", protocolstate.ExecutionIDFromContext(ctx))
}
