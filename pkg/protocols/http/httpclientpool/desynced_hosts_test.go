package httpclientpool

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/retryablehttp-go"
)

// TestMarkHostDesyncedStopsReuse verifies the behaviour that matters: requests to a
// marked host stop sharing a connection, requests to any other host keep sharing
// one, and the keep-alive client cached for the host before the mark is not handed
// out again.
func TestMarkHostDesyncedStopsReuse(t *testing.T) {
	opts := newTestOptions(t, "test-desynced-host-no-reuse")
	cfg := &Configuration{}

	var conns atomic.Int64
	// Unstarted, because Server.Config must not be touched once it is serving.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	host := hostOf(t, server.URL)

	pooled, err := Get(opts, cfg, host)
	require.NoError(t, err)
	requestTwice(t, pooled, server.URL)
	require.Equal(t, int64(1), conns.Load(), "an unmarked host must reuse its connection")

	MarkHostDesynced(server.URL)
	t.Cleanup(func() { desyncedHosts.Delete(host) })
	require.True(t, IsHostDesynced(host), "a mark set from a URL must match a host:port lookup")

	guarded, err := Get(opts, cfg, host)
	require.NoError(t, err)
	require.NotSame(t, pooled, guarded,
		"a marked host must not be served the keep-alive client cached earlier")

	conns.Store(0)
	requestTwice(t, guarded, server.URL)
	require.Equal(t, int64(2), conns.Load(), "a marked host must not reuse connections")
}

// TestIsHostDesyncedExpires checks the mark does not pin a host forever: attribution
// of a detection to a host is not always exact, so an innocent host must recover.
func TestIsHostDesyncedExpires(t *testing.T) {
	const host = "expiring.example.com"

	desyncedHosts.Store(host, time.Now().Add(-desyncedHostTTL-time.Minute))
	t.Cleanup(func() { desyncedHosts.Delete(host) })

	require.False(t, IsHostDesynced(host), "a mark older than the TTL must not apply")

	_, still := desyncedHosts.Load(host)
	require.False(t, still, "an expired mark must be dropped")
}

// TestIsHostDesyncedEmptyHost guards the case where the caller could not resolve a
// host: an empty mark would otherwise disable reuse for every unnamed lookup.
func TestIsHostDesyncedEmptyHost(t *testing.T) {
	MarkHostDesynced("")
	require.False(t, IsHostDesynced(""))
}

func requestTwice(t *testing.T, client *retryablehttp.Client, target string) {
	t.Helper()

	for range 2 {
		resp, err := client.Get(target)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()

	parsed, err := url.Parse(raw)
	require.NoError(t, err)

	return parsed.Host
}

// TestDesyncedHostKey pins the normalization: a mark and a lookup must agree whether
// the caller had a URL, a host:port, or a bare host, and different ports on the same
// host must stay independent.
func TestDesyncedHostKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://example.com:8443/admin?a=1", "example.com:8443"},
		{"http://example.com/", "example.com"},
		{"example.com:8443", "example.com:8443"},
		{"  example.com  ", "example.com"},
		{"", ""},
	} {
		require.Equal(t, tc.want, desyncedHostKey(tc.in), tc.in)
	}

	require.NotEqual(t, desyncedHostKey("example.com:80"), desyncedHostKey("example.com:8080"))
}
