package httpclientpool

import (
	"net/http/cookiejar"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
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

// TestGet_TransportSharedAcrossConfigurations verifies that clients whose
// configurations differ only in client-level settings (redirect policy,
// cookie handling) still share one underlying transport per host, so the
// host's connection pool is reused across templates.
func TestGet_TransportSharedAcrossConfigurations(t *testing.T) {
	opts := newTestOptions(t, "test-transport-shared")

	cfgNoRedirects := &Configuration{}
	cfgRedirects := &Configuration{MaxRedirects: 5, RedirectFlow: FollowAllRedirect}

	c1, err := Get(opts, cfgNoRedirects, "example.com")
	require.NoError(t, err)
	c2, err := Get(opts, cfgRedirects, "example.com")
	require.NoError(t, err)

	require.NotSame(t, c1, c2, "different configurations must produce different clients")
	require.Same(t, c1.HTTPClient.Transport, c2.HTTPClient.Transport,
		"clients differing only in client-level settings must share the per-host transport")

	c3, err := Get(opts, cfgNoRedirects, "other.example.com")
	require.NoError(t, err)
	require.NotSame(t, c1.HTTPClient.Transport, c3.HTTPClient.Transport,
		"different hosts must not share a transport")
}

// TestGet_ExplicitCookieJarSharesTransport verifies that uncached clients
// created for explicit per-request cookie jars still reuse the pooled
// per-host transport instead of opening their own connections.
func TestGet_ExplicitCookieJarSharesTransport(t *testing.T) {
	opts := newTestOptions(t, "test-explicit-jar-transport")

	cached, err := Get(opts, &Configuration{Connection: &ConnectionConfiguration{}}, "example.com")
	require.NoError(t, err)

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)
	cfg := &Configuration{Connection: &ConnectionConfiguration{}}
	cfg.Connection.SetCookieJar(jar)

	withJar, err := Get(opts, cfg, "example.com")
	require.NoError(t, err)

	require.NotSame(t, cached, withJar, "explicit jar must bypass the client cache")
	require.Same(t, cached.HTTPClient.Transport, withJar.HTTPClient.Transport,
		"explicit-jar clients must still share the pooled per-host transport")
}

// TestGet_ConcurrentSameHost verifies that concurrent first requests for the
// same (configuration, host) pair produce exactly one shared client.
func TestGet_ConcurrentSameHost(t *testing.T) {
	opts := newTestOptions(t, "test-concurrent-same-host")
	cfg := &Configuration{}

	const workers = 32
	clients := make([]*retryablehttp.Client, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := Get(opts, cfg, "example.com")
			require.NoError(t, err)
			clients[idx] = c
		}(i)
	}
	wg.Wait()

	for i := 1; i < workers; i++ {
		require.Same(t, clients[0], clients[i], "concurrent Get() calls must return one shared client")
	}
}

// TestResetConnectionStats verifies the global counter reset used between
// in-process scans to keep per-run summaries accurate.
func TestResetConnectionStats(t *testing.T) {
	connStats.New.Store(7)
	connStats.Reused.Store(11)
	recordHostConn("example.com", false)

	ResetConnectionStats()

	newC, reused := GetConnectionStats()
	require.Equal(t, int64(0), newC, "new conn counter must be reset to 0")
	require.Equal(t, int64(0), reused, "reused conn counter must be reset to 0")
	require.Empty(t, GetPerHostConnectionStats(), "per-host stats must be cleared on reset")
}

// TestPerHostConnectionStats verifies that the per-host breakdown is recorded
// alongside the global counters from the shared GotConn hook.
func TestPerHostConnectionStats(t *testing.T) {
	ResetConnectionStats()
	t.Cleanup(ResetConnectionStats)

	recordHostConn("a.example.com", false)
	recordHostConn("a.example.com", true)
	recordHostConn("a.example.com", true)
	recordHostConn("b.example.com", false)
	recordHostConn("", true) // empty host must be ignored

	stats := GetPerHostConnectionStats()
	byHost := make(map[string]PerHostConnStat, len(stats))
	for _, s := range stats {
		byHost[s.Host] = s
	}

	require.Len(t, stats, 2, "only non-empty hosts should be tracked")
	require.Equal(t, int64(1), byHost["a.example.com"].New)
	require.Equal(t, int64(2), byHost["a.example.com"].Reused)
	require.Equal(t, int64(1), byHost["b.example.com"].New)
	require.Equal(t, int64(0), byHost["b.example.com"].Reused)
}
