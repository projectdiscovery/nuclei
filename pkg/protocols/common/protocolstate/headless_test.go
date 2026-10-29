package protocolstate

import (
	"testing"

	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestIsValidHost(t *testing.T) {
	opts := &types.Options{
		ExecutionId: "test-exec-id",
	}

	np, err := networkpolicy.New(networkpolicy.Options{
		DenyList: []string{"127.0.0.1"},
	})
	require.NoError(t, err)

	d := &Dialers{
		NetworkPolicy: np,
	}
	err = dialers.Set(opts.ExecutionId, d)
	require.NoError(t, err)
	defer dialers.Delete(opts.ExecutionId)

	// Allowed remote hosts
	require.True(t, isValidHost(opts, "http://example.com"))
	require.True(t, isValidHost(opts, "https://example.com"))
	require.True(t, isValidHost(opts, "ws://example.com:9999"))
	require.True(t, isValidHost(opts, "wss://example.com:9999"))

	// Blocked hosts (127.0.0.1)
	require.False(t, isValidHost(opts, "http://127.0.0.1:8080"))
	require.False(t, isValidHost(opts, "https://127.0.0.1:8443"))
	require.False(t, isValidHost(opts, "ws://127.0.0.1:9999"))
	require.False(t, isValidHost(opts, "wss://127.0.0.1:9999"))

	require.True(t, IsHostAllowed(opts.ExecutionId, "ws://example.com:9999"))
	require.False(t, IsHostAllowed(opts.ExecutionId, "ws://127.0.0.1:9999"))

	// IPv4-mapped IPv6 forms of a blocked IPv4 host
	for _, target := range []string{
		"http://[::ffff:127.0.0.1]:8080/",
		"https://[::ffff:7f00:1]/",
		"http://[0:0:0:0:0:ffff:127.0.0.1]/",
		"ws://[::ffff:127.0.0.1]:9999",
	} {
		require.False(t, isValidHost(opts, target), target)
		require.False(t, IsHostAllowed(opts.ExecutionId, target), target)
	}
	require.True(t, isValidHost(opts, "http://[::ffff:8.8.8.8]/"))
}

func TestSetupHeadlessNetworkPolicy_Nil(t *testing.T) {
	require.NoError(t, SetupHeadlessNetworkPolicy(nil, nil))
	require.NoError(t, SetupHeadlessNetworkPolicy(&types.Options{}, nil))
}

