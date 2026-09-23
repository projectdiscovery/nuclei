package smb

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const deniedHost = "203.0.113.50" // TEST-NET-3; no DNS needed for policy checks

func TestListDirDeniesHostBeforeDial(t *testing.T) {
	executionID := "smb-listdir-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{deniedHost},
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ListDir(ctx, deniedHost, 445, "user", "pass", "share", ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), deniedHost)
}

func TestReadFileDeniesHostBeforeDial(t *testing.T) {
	executionID := "smb-readfile-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{deniedHost},
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ReadFile(ctx, deniedHost, 445, "user", "pass", "share", "a.txt")
	require.Error(t, err)
	require.Contains(t, err.Error(), deniedHost)
}

func TestListTreeDeniesHostBeforeDial(t *testing.T) {
	executionID := "smb-listtree-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{deniedHost},
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ListTree(ctx, deniedHost, 445, "user", "pass", "share", ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), deniedHost)
}

func TestListSharesDeniesHostBeforeDial(t *testing.T) {
	executionID := "smb-listshares-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{deniedHost},
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ListShares(ctx, deniedHost, 445, "user", "pass")
	require.Error(t, err)
	require.Contains(t, err.Error(), deniedHost)
}

func TestListDirRejectsEmptyShare(t *testing.T) {
	executionID := "smb-empty-share"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ListDir(ctx, "127.0.0.1", 445, "user", "pass", "", ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), "share name cannot be empty")
}

func TestListDirRejectsShareWithSeparator(t *testing.T) {
	executionID := "smb-bad-share"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck
	_, err := (&SMBClient{}).ListDir(ctx, "127.0.0.1", 445, "user", "pass", `evil\share`, ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), "path separators")
}
