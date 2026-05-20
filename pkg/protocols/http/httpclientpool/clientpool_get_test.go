package httpclientpool

import (
	"net/http/cookiejar"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// newTestOptions returns a fresh *types.Options with a unique ExecutionId so
// tests do not share the package-global dialers/HTTPClientPool state.
func newTestOptions(t *testing.T, executionId string) *types.Options {
	t.Helper()
	opts := types.DefaultOptions()
	opts.SetExecutionID(executionId)
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	return opts
}

// TestGet_HostScopedCache verifies that two Get() calls for the same host with
// the same configuration return the same cached *retryablehttp.Client, while
// different hosts produce different clients (per-host pool isolation).
func TestGet_HostScopedCache(t *testing.T) {
	opts := newTestOptions(t, "test-host-scoped-cache")
	cfg := &Configuration{}

	c1, err := Get(opts, cfg, "example.com")
	require.NoError(t, err)
	require.NotNil(t, c1)

	c2, err := Get(opts, cfg, "example.com")
	require.NoError(t, err)
	require.Same(t, c1, c2, "second Get() for the same host must hit the cache")

	c3, err := Get(opts, cfg, "other.example.com")
	require.NoError(t, err)
	require.NotSame(t, c1, c3, "different hosts must produce different clients")
}

// TestGet_ExplicitCookieJarBypassesCache verifies that callers passing an
// explicit per-request cookie jar always receive a fresh client (so per-request
// session state is never leaked into the shared pool).
func TestGet_ExplicitCookieJarBypassesCache(t *testing.T) {
	opts := newTestOptions(t, "test-explicit-jar-bypass")

	jar1, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)
	cfg1 := &Configuration{Connection: &ConnectionConfiguration{}}
	cfg1.Connection.SetCookieJar(jar1)

	c1, err := Get(opts, cfg1, "example.com")
	require.NoError(t, err)
	require.NotNil(t, c1)

	jar2, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)
	cfg2 := &Configuration{Connection: &ConnectionConfiguration{}}
	cfg2.Connection.SetCookieJar(jar2)

	c2, err := Get(opts, cfg2, "example.com")
	require.NoError(t, err)
	require.NotSame(t, c1, c2, "explicit cookie jars must always bypass the cache")
}

// TestGet_DisableKeepAliveAffectsCacheKey verifies that Configuration.Hash
// distinguishes clients that differ only in DisableKeepAlive, so the pool
// cannot return a client with the wrong keep-alive semantics.
func TestGet_DisableKeepAliveAffectsCacheKey(t *testing.T) {
	opts := newTestOptions(t, "test-disable-keepalive-hash")

	cfgKeepAliveOn := &Configuration{
		Connection: &ConnectionConfiguration{DisableKeepAlive: false},
	}
	cfgKeepAliveOff := &Configuration{
		Connection: &ConnectionConfiguration{DisableKeepAlive: true},
	}

	require.NotEqual(t, cfgKeepAliveOn.Hash(), cfgKeepAliveOff.Hash(),
		"Configuration.Hash() must encode DisableKeepAlive to avoid pool-key collisions")

	cOn, err := Get(opts, cfgKeepAliveOn, "example.com")
	require.NoError(t, err)
	cOff, err := Get(opts, cfgKeepAliveOff, "example.com")
	require.NoError(t, err)
	require.NotSame(t, cOn, cOff,
		"clients with different DisableKeepAlive must not share a cache entry")

	// Sanity check the underlying transport actually reflects the flag.
	require.NotNil(t, cOn.HTTPClient.Transport)
	require.NotNil(t, cOff.HTTPClient.Transport)
}

// TestResetConnectionStats verifies the global counter reset used between
// in-process scans to keep per-run summaries accurate.
func TestResetConnectionStats(t *testing.T) {
	connStats.New.Store(7)
	connStats.Reused.Store(11)

	ResetConnectionStats()

	newC, reused := GetConnectionStats()
	require.Equal(t, int64(0), newC, "new conn counter must be reset to 0")
	require.Equal(t, int64(0), reused, "reused conn counter must be reset to 0")
}
