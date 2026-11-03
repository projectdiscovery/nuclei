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
		NetworkPolicy:  np,
		ExcludeTargets: []string{"192.168.1.50"},
	}
	err = dialers.Set(opts.ExecutionId, d)
	require.NoError(t, err)
	defer dialers.Delete(opts.ExecutionId)

	// Allowed remote hosts
	require.True(t, isValidHost(opts, "http://example.com"))
	require.True(t, isValidHost(opts, "https://example.com"))
	require.True(t, isValidHost(opts, "ws://example.com:9999"))
	require.True(t, isValidHost(opts, "wss://example.com:9999"))

	// Blocked hosts (127.0.0.1 in DenyList)
	require.False(t, isValidHost(opts, "http://127.0.0.1:8080"))
	require.False(t, isValidHost(opts, "https://127.0.0.1:8443"))
	require.False(t, isValidHost(opts, "ws://127.0.0.1:9999"))
	require.False(t, isValidHost(opts, "wss://127.0.0.1:9999"))

	// Blocked IPv4-mapped IPv6 forms of 127.0.0.1
	require.False(t, isValidHost(opts, "http://[::ffff:127.0.0.1]:8080"))
	require.False(t, isValidHost(opts, "https://[::ffff:127.0.0.1]:8443"))
	require.False(t, isValidHost(opts, "http://[::ffff:7f00:1]:8080"))
	require.False(t, isValidHost(opts, "http://[0:0:0:0:0:ffff:127.0.0.1]:8080"))
	require.False(t, isValidHost(opts, "http://[0000:0000:0000:0000:0000:ffff:7f00:0001]:8080"))
	require.False(t, isValidHost(opts, "ws://[::ffff:127.0.0.1]:9999"))

	// Blocked hosts via ExcludeTargets (IPv4 and IPv4-mapped IPv6)
	require.False(t, isValidHost(opts, "http://192.168.1.50:8080"))
	require.False(t, isValidHost(opts, "http://[::ffff:192.168.1.50]:8080"))
	require.False(t, isValidHost(opts, "http://[::ffff:c0a8:132]:8080"))

	require.True(t, IsHostAllowed(opts.ExecutionId, "ws://example.com:9999"))
	require.False(t, IsHostAllowed(opts.ExecutionId, "ws://127.0.0.1:9999"))
	require.False(t, IsHostAllowed(opts.ExecutionId, "ws://[::ffff:127.0.0.1]:9999"))
	require.False(t, IsHostAllowed(opts.ExecutionId, "http://[::ffff:192.168.1.50]:8080"))
}

func TestIsHostAllowedMappedFormOfAllowListedIP(t *testing.T) {
	const executionID = "test-allow-mapped"
	opts := &types.Options{ExecutionId: executionID}

	np, err := networkpolicy.New(networkpolicy.Options{
		AllowList: []string{"203.0.113.10"},
		DenyList:  []string{"127.0.0.1"},
	})
	require.NoError(t, err)

	err = dialers.Set(executionID, &Dialers{NetworkPolicy: np})
	require.NoError(t, err)
	defer dialers.Delete(executionID)

	require.True(t, isValidHost(opts, "http://203.0.113.10"))
	require.True(t, isValidHost(opts, "http://[::ffff:203.0.113.10]"))
	require.True(t, isValidHost(opts, "http://[::ffff:cb00:710a]:8080"))
	require.False(t, isValidHost(opts, "http://[::ffff:127.0.0.1]"))
	require.False(t, isValidHost(opts, "http://198.51.100.1"))
}

func TestCanonicalizeHost_IPv4MappedIPv6(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":                                "127.0.0.1",
		"127.0.0.1:8080":                           "127.0.0.1:8080",
		"::ffff:127.0.0.1":                         "127.0.0.1",
		"[::ffff:127.0.0.1]":                       "127.0.0.1",
		"[::ffff:127.0.0.1]:8080":                  "127.0.0.1:8080",
		"::ffff:7f00:1":                            "127.0.0.1",
		"[::ffff:7f00:1]:8443":                     "127.0.0.1:8443",
		"0:0:0:0:0:ffff:127.0.0.1":                 "127.0.0.1",
		"0000:0000:0000:0000:0000:ffff:7f00:0001": "127.0.0.1",
		"example.com":                              "example.com",
		"example.com:443":                          "example.com:443",
		"::1":                                      "::1",
		"[::1]:8080":                               "[::1]:8080",
	}

	for input, expected := range cases {
		require.Equal(t, expected, CanonicalizeHost(input), "input: %s", input)
	}
}

func TestSetupHeadlessNetworkPolicy_Nil(t *testing.T) {
	require.NoError(t, SetupHeadlessNetworkPolicy(nil, nil))
	require.NoError(t, SetupHeadlessNetworkPolicy(&types.Options{}, nil))
}
