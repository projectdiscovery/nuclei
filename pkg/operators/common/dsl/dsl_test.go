package dsl

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDslExpressions(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		question := request.Question[0]
		var record string
		switch question.Qtype {
		case dns.TypeA:
			record = "fixture.example. 60 IN A 128.199.158.128"
		case dns.TypeAAAA:
			record = "fixture.example. 60 IN AAAA 2400:6180:0:d0::91:1001"
		case dns.TypeSOA:
			record = "fixture.example. 60 IN SOA ns.example. admin.example. 1 60 60 60 60"
		case dns.TypeSRV:
			record = "_service._tcp.fixture.example. 60 IN SRV 0 0 443 server.example."
		}
		if record != "" {
			answer, parseErr := dns.NewRR(record)
			if parseErr == nil {
				response.Answer = []dns.RR{answer}
			}
		}
		_ = writer.WriteMsg(response)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	options := networkTestOptions(t, &types.Options{RestrictLocalNetworkAccess: true, InternalResolversList: []string{listener.LocalAddr().String()}})
	for expression, expected := range map[string]string{
		`resolve("fixture.example")`:                      "128.199.158.128",
		`resolve("f\\105xture.example")`:                  "128.199.158.128",
		`resolve("f\\ixture.example")`:                    "128.199.158.128",
		`resolve("fixture.example", "a")`:                 "128.199.158.128",
		`resolve("fixture.example", "6")`:                 "2400:6180:0:d0::91:1001",
		`resolve("fixture.example", "aaaa")`:              "2400:6180:0:d0::91:1001",
		`resolve("fixture.example", "soa")`:               "ns.example",
		`resolve("_service._tcp.fixture.example", "srv")`: "server.example",
	} {
		t.Run(expression, func(t *testing.T) {
			result, err := evalNetworkTest(t, expression, options)
			require.NoError(t, err)
			require.Equal(t, expected, result)
		})
	}
}
