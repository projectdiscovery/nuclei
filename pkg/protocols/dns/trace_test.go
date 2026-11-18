package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/retryabledns"
)

func serveTraceDNS(t *testing.T, address string, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", address)
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSTraceObeysNetworkPolicy(t *testing.T) {
	// The zone of the traced name delegates to a name server on 127.0.0.1.
	// The trace must query it when the policy allows the address, so that the
	// test can see a trace that ignores the policy, and must skip it when the
	// policy denies the address.
	t.Run("allowed", func(t *testing.T) {
		require.NotZero(t, runTraceAgainstLoopbackNameServer(t, nil), "trace did not query the allowed name server")
	})
	t.Run("denied", func(t *testing.T) {
		require.Zero(t, runTraceAgainstLoopbackNameServer(t, []string{"127.0.0.1"}), "trace queried a denied name server")
	})
}

func runTraceAgainstLoopbackNameServer(t *testing.T, excludeTargets []string) int32 {
	t.Helper()
	var internalHits atomic.Int32
	internal := serveTraceDNS(t, "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		internalHits.Add(1)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + ` 0 IN TXT "internal"`)
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	_, port, err := net.SplitHostPort(internal)
	require.NoError(t, err)
	previousPort := traceNameServerPort
	traceNameServerPort = port
	t.Cleanup(func() { traceNameServerPort = previousPort })

	// public stands in for the root servers, the scan resolvers and the system resolver
	public := serveTraceDNS(t, "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		question := q.Question[0]
		var rr dns.RR
		switch {
		case question.Name == "ns.nuclei-test." && question.Qtype == dns.TypeA:
			rr, _ = dns.NewRR("ns.nuclei-test. 0 IN A 127.0.0.1")
		case question.Name == "ns.nuclei-test.":
		case question.Name == "trace.nuclei-test.":
			rr, _ = dns.NewRR("trace.nuclei-test. 0 IN NS ns.nuclei-test.")
		default:
			rr, _ = dns.NewRR(question.Name + ` 0 IN TXT "public"`)
		}
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	previousRoots := retryabledns.RootDNSServersIPv4
	retryabledns.RootDNSServersIPv4 = []string{public}
	t.Cleanup(func() { retryabledns.RootDNSServersIPv4 = previousRoots })
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", public)
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previousResolver })

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = excludeTargets
	options.InternalResolversList = []string{public}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "dns-trace-policy",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})

	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: TXT},
		Class:       "INET",
		Name:        "{{FQDN}}",
		// One retry keeps the client keyed by this test's resolvers, so a
		// client cached by an earlier run cannot point at a closed server.
		Retries:           1,
		Trace:             true,
		TraceMaxRecursion: 5,
	}
	require.NoError(t, request.Compile(executerOpts))

	var event output.InternalEvent
	input := contextargs.NewWithInput(context.Background(), "trace.nuclei-test")
	err = request.ExecuteWithResults(input, nil, nil, func(e *output.InternalWrappedEvent) {
		event = e.InternalEvent
	})
	require.NoError(t, err)
	require.Contains(t, event["trace"], "ns.nuclei-test", "trace did not query the root servers")
	return internalHits.Load()
}
