package dnsclientpool

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		internal := newDohServer(t, &hits)
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/internal", http.StatusFound)
		}))
		t.Cleanup(redirector.Close)
		// localhost passes the resolver check through ::1, while 127.0.0.1 is denied
		_, port, err := net.SplitHostPort(strings.TrimPrefix(redirector.URL, "http://"))
		require.NoError(t, err)
		options := dohOptions(t, []string{"127.0.0.1"})
		require.True(t, protocolstate.IsHostAllowed(options.ExecutionId, "localhost"))

		client, err := Get(options, &Configuration{Retries: 1, Resolvers: []string{"doh:http://localhost:" + port + "/dns-query:get"}})
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
