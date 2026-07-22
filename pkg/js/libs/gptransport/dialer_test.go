package gptransport_test

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/gptransport"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDialWithExecDeniesExcludedHost(t *testing.T) {
	execID := "gptransport-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.50"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	_, err := gptransport.DialWithExec(context.Background(), execID, "tcp", "203.0.113.50:445")
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.50")
}

func TestExecutionIDFromCtx(t *testing.T) {
	require.Equal(t, "", gptransport.ExecutionIDFromCtx(nil))
	require.Equal(t, "", gptransport.ExecutionIDFromCtx(context.Background()))
	ctx := context.WithValue(context.Background(), "executionId", "abc") //nolint:staticcheck
	require.Equal(t, "abc", gptransport.ExecutionIDFromCtx(ctx))
}

func TestNewExecDialerEmptyID(t *testing.T) {
	d := gptransport.NewExecDialer("")
	require.NotNil(t, d)
}
