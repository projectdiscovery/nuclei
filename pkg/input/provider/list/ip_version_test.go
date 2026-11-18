package list

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// A local deterministic DNS responder for dual-stack, A-only and AAAA-only hosts.
type ipVersionDNSHandler struct{}

func (ipVersionDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(r)
	if len(r.Question) == 0 {
		_ = w.WriteMsg(reply)
		return
	}
	question := r.Question[0]
	// Some resolvers try search suffixes before the absolute name. Match the
	// test host prefix rather than answering unrelated names as dual-stack.
	host := strings.ToLower(question.Name)
	if strings.HasPrefix(host, "empty.") {
		_ = w.WriteMsg(reply)
		return
	}
	isDual := strings.HasPrefix(host, "dual.")
	isV4 := strings.HasPrefix(host, "v4only.")
	isV6 := strings.HasPrefix(host, "v6only.")
	if question.Qtype == dns.TypeA && (isDual || isV4) {
		reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.10")})
	}
	if question.Qtype == dns.TypeAAAA && (isDual || isV6) {
		reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::10")})
	}
	_ = w.WriteMsg(reply)
}

func TestIPVersionsDefaultAndExplicitSelection(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, Handler: ipVersionDNSHandler{}, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS test resolver did not start")
	}
	opts := types.DefaultOptions()
	opts.ExecutionId = "ip-version-regression"
	opts.InternalResolversList = []string{conn.LocalAddr().String()}
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	for _, tc := range []struct {
		name, hostname            string
		scanAll, ipv4, ipv6, auto bool
		want                      []string
	}{
		{"automatic dual-stack keeps dialer fallback", "dual.test", false, true, true, true, []string{""}},
		{"automatic IPv6-only keeps dialer fallback", "v6only.test", false, true, true, true, []string{""}},
		{"auto IPv4 fallback", "v4only.test", false, true, true, true, []string{""}},
		{"auto empty DNS response fallback", "empty.test", false, true, true, true, []string{""}},
		{"all empty DNS response fallback", "empty.test", true, true, true, true, []string{""}},
		{"all dual", "dual.test", true, true, true, true, []string{"192.0.2.10", "2001:db8::10"}},
		{"all IPv6 only", "v6only.test", true, true, true, true, []string{"2001:db8::10"}},
		{"all IPv4 only", "v4only.test", true, true, true, true, []string{"192.0.2.10"}},
		{"explicit IPv4 only", "dual.test", false, true, false, false, []string{""}},
		{"explicit IPv6 only", "dual.test", false, false, true, false, []string{"2001:db8::10"}},
		{"explicit both", "dual.test", false, true, true, false, []string{"2001:db8::10", ""}},
		{"all explicit IPv6", "dual.test", true, false, true, false, []string{"2001:db8::10"}},
		{"all explicit IPv4", "dual.test", true, true, false, false, []string{"192.0.2.10"}},
		{"IPv6 restricted on IPv4-only", "v4only.test", true, false, true, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hm, err := hybrid.New(hybrid.DefaultDiskOptions)
			require.NoError(t, err)
			input := &ListInputProvider{
				hostMap:       hm,
				excludedHosts: make(map[string]struct{}),
				ipOptions:     &ipOptions{ScanAllIPs: tc.scanAll, IPV4: tc.ipv4, IPV6: tc.ipv6, Auto: tc.auto},
			}
			t.Cleanup(input.Close)
			input.Set(opts.ExecutionId, "https://"+tc.hostname)
			var got []string
			input.Iterate(func(value *contextargs.MetaInput) bool {
				got = append(got, value.CustomIP)
				return true
			})
			require.ElementsMatch(t, tc.want, got)
			if tc.scanAll && len(tc.want) > 0 {
				input.Del(opts.ExecutionId, "https://"+tc.hostname)
				require.EqualValues(t, 0, input.Count(), "Del must remove the same IPs added by Set")
			}
		})
	}
}
