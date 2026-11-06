package dnsclientpool

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// newDotListener accepts TCP connections on 127.0.0.1, counts them and closes
// them, so a test sees each DoT dial that reaches the address.
func newDotListener(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	return port
}

func TestDotResolverObeysNetworkPolicy(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost"} {
		t.Run("denied address "+host, func(t *testing.T) {
			var hits atomic.Int32
			port := newDotListener(t, &hits)
			// localhost passes the resolver check through ::1, while 127.0.0.1 is denied
			options := dohOptions(t, []string{"127.0.0.1"})

			client, err := Get(options, &Configuration{Retries: 2, Resolvers: []string{"dot:" + net.JoinHostPort(host, port)}})
			require.NoError(t, err)
			_, _ = client.Do(txtQuery())
			require.Zero(t, hits.Load(), "DoT query reached a denied address")
		})
	}

	t.Run("allowed address", func(t *testing.T) {
		var hits atomic.Int32
		port := newDotListener(t, &hits)
		options := dohOptions(t, nil)

		client, err := Get(options, &Configuration{Retries: 1, Resolvers: []string{"dot:127.0.0.1:" + port}})
		require.NoError(t, err)
		_, _ = client.Do(txtQuery())
		require.Equal(t, int32(1), hits.Load())
	})
}

func TestDotResolverAnswers(t *testing.T) {
	// httptest gives a certificate for 127.0.0.1 and a pool that trusts it.
	certs := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certs.Close)
	previous := dotRootCAs
	dotRootCAs = certs.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	t.Cleanup(func() { dotRootCAs = previous })

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs.TLS.Certificates, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	server := &dns.Server{Listener: l, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(`example.com. 60 IN TXT "dot-answer"`)
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	options := dohOptions(t, nil)
	client, err := Get(options, &Configuration{Retries: 2, Resolvers: []string{"dot:" + l.Addr().String()}})
	require.NoError(t, err)
	resp, err := client.Do(txtQuery())
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)
	require.Contains(t, resp.Answer[0].String(), "dot-answer")
}
