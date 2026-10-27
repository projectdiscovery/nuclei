package protocolstate

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExcludeTargetsMatchExactHost(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ExecutionId = "test-exclude-targets"
	opts.ExcludeTargets = []string{"test.com", "192.0.2.0/24"}
	require.NoError(t, Init(opts))
	defer Close(opts.ExecutionId)

	np := GetDialersWithId(opts.ExecutionId).NetworkPolicy
	require.False(t, np.Validate("test.com"))
	require.False(t, np.Validate("TEST.com"))
	require.False(t, np.Validate("192.0.2.10"))
	require.True(t, np.Validate("latest.com"))
	require.True(t, np.Validate("test.com.example.org"))
	require.True(t, np.Validate("testXcom"))
}
