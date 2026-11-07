package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
)

// startDNSServer answers every query with a TXT record, or with the A records
// in addrs when the question is for name, and counts the queries.
func startDNSServer(t *testing.T, name string, addrs []string, hits *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(q)
		question := q.Question[0]
		switch {
		case question.Name == name && question.Qtype == dns.TypeA:
			for _, addr := range addrs {
				rr, _ := dns.NewRR(name + " 0 IN A " + addr)
				m.Answer = append(m.Answer, rr)
			}
		case question.Name == name:
		default:
			rr, _ := dns.NewRR(question.Name + ` 0 IN TXT "answer"`)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	require.NoError(t, err)
	tcpServer := &dns.Server{Listener: l, Handler: server.Handler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = tcpServer.Shutdown() })
	return pc.LocalAddr().String()
}

// useSystemResolver sends the lookups of the process to the DNS server at address.
func useSystemResolver(t *testing.T, address string) {
	t.Helper()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", address)
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previous })
}

func TestDNSResolverNameObeysNetworkPolicy(t *testing.T) {
	// The resolver name has an allowed address and a denied address. The
	// policy check passes because one address is allowed, so the query must
	// not go to the denied one.
	var deniedHits, systemHits atomic.Int32
	denied := startDNSServer(t, "", nil, &deniedHits)
	_, port, err := net.SplitHostPort(denied)
	require.NoError(t, err)
	system := startDNSServer(t, "resolver.nuclei-test.", []string{"127.0.0.1", "127.0.0.2"}, &systemHits)
	useSystemResolver(t, system)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"127.0.0.1"}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "dns-resolver-policy",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})

	for _, resolver := range []string{"resolver.nuclei-test:" + port, "tcp:resolver.nuclei-test:" + port} {
		t.Run(resolver, func(t *testing.T) {
			deniedHits.Store(0)
			request := &Request{
				RequestType: DNSRequestTypeHolder{DNSRequestType: TXT},
				Class:       "INET",
				Retries:     2,
				Name:        "{{FQDN}}",
				Resolvers:   []string{resolver},
			}
			require.NoError(t, request.Compile(executerOpts))

			msg := new(dns.Msg)
			msg.SetQuestion("example.com.", dns.TypeTXT)
			_, _ = request.dnsClient.Do(msg)
			require.Zero(t, deniedHits.Load(), "dns query reached a denied address")
		})
	}
}

func TestDNSResolverNameLookupStopsAtTimeout(t *testing.T) {
	// The system resolver never answers, so the lookup that pins the resolver
	// name must stop at the timeout.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = silent.Close() })
	useSystemResolver(t, silent.LocalAddr().String())

	start := time.Now()
	_, err = pinResolverHost(t.Name(), "silent.nuclei-test:53", "silent.nuclei-test", time.Second)
	require.Error(t, err)
	require.Less(t, time.Since(start), 4*time.Second, "the resolver lookup did not stop at the timeout")
}
