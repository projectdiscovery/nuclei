package dnsclientpool

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// newDohServer answers every DoH query with a TXT record and counts the hits.
func newDohServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return newDohServerOn(t, hits, "127.0.0.1:0")
}

// newDohServerOn is newDohServer bound to address, so a test can separate an
// allowed redirector from a denied target.
func newDohServerOn(t *testing.T, hits *atomic.Int32, address string) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeTXT)
		m.Response = true
		rr, err := dns.NewRR(`example.com. 60 IN TXT "doh-answer"`)
		require.NoError(t, err)
		m.Answer = append(m.Answer, rr)
		packed, err := m.Pack()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func dohOptions(t *testing.T, excludeTargets []string) *types.Options {
	t.Helper()
	options := types.DefaultOptions()
	options.ExecutionId = t.Name()
	options.ExcludeTargets = excludeTargets
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })
	require.NoError(t, Init(options))
	return options
}

func txtQuery() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeTXT)
	return msg
}

func TestDohResolverObeysNetworkPolicy(t *testing.T) {
	t.Run("denied address", func(t *testing.T) {
		var hits atomic.Int32
		internal := newDohServer(t, &hits)
		options := dohOptions(t, []string{"127.0.0.1"})

		client, err := Get(options, &Configuration{Retries: 1, Resolvers: []string{"doh:" + internal.URL + "/dns-query:get"}})
		require.NoError(t, err)
		_, _ = client.Do(txtQuery())
		require.Zero(t, hits.Load(), "DoH query reached a denied address")
	})

	t.Run("redirect to denied address", func(t *testing.T) {
		var hits atomic.Int32
		// The target listens on ::1, which is denied. The redirector stays on
		// 127.0.0.1. localhost cannot be the allowed hop: denying 127.0.0.1
		// denies localhost too, because that name resolves to 127.0.0.1.
		internal := newDohServerOn(t, &hits, "[::1]:0")
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/internal", http.StatusFound)
		}))
		t.Cleanup(redirector.Close)
		options := dohOptions(t, []string{"::1"})
		require.True(t, protocolstate.IsHostAllowed(options.ExecutionId, "127.0.0.1"))
		require.False(t, protocolstate.IsHostAllowed(options.ExecutionId, "::1"))

		client, err := Get(options, &Configuration{Retries: 1, Resolvers: []string{"doh:" + redirector.URL + "/dns-query:get"}})
		require.NoError(t, err)
		_, _ = client.Do(txtQuery())
		require.Zero(t, hits.Load(), "DoH redirect reached a denied address")
	})

	t.Run("allowed address", func(t *testing.T) {
		var hits atomic.Int32
		server := newDohServer(t, &hits)
		options := dohOptions(t, nil)

		client, err := Get(options, &Configuration{Retries: 2, Resolvers: []string{"doh:" + server.URL + "/dns-query:get"}})
		require.NoError(t, err)
		resp, err := client.Do(txtQuery())
		require.NoError(t, err)
		require.Len(t, resp.Answer, 1)
		require.Equal(t, int32(1), hits.Load())
	})
}
