package http

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/stretchr/testify/require"
)

func TestRequestNetworkDSLPolicy(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var queries atomic.Int32
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg).SetReply(r)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("8.8.8.8")}}
		_ = w.WriteMsg(response)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	for _, item := range []struct {
		name              string
		restrict, exclude bool
	}{
		{name: "default"}, {name: "restricted", restrict: true},
		{name: "excluded without lna", exclude: true}, {name: "excluded with lna", restrict: true, exclude: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			options := testutils.DefaultOptions.Copy()
			options.ExecutionId = t.Name()
			options.RestrictLocalNetworkAccess = item.restrict
			options.InternalResolversList = []string{listener.LocalAddr().String()}
			if item.exclude {
				options.ExcludeTargets = []string{"8.8.8.8"}
			}
			require.NoError(t, protocolinit.Init(options))
			t.Cleanup(func() { protocolinit.Close(options.ExecutionId) })
			executor := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executor.RateLimiter.Stop)
			request := &Request{Method: HTTPMethodTypeHolder{MethodType: HTTPPost}, Path: []string{"{{BaseURL}}"}, Body: `{{resolve("fixture.example")}}`}
			require.NoError(t, request.Compile(executor))
			generator := request.newGenerator(false)
			input, payloads, _ := generator.nextValue()
			before := queries.Load()
			generated, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), input, payloads, nil)
			if item.exclude {
				require.ErrorContains(t, err, "network policy")
			} else {
				require.NoError(t, err)
				body, err := generated.request.BodyBytes()
				require.NoError(t, err)
				require.Equal(t, "8.8.8.8", string(body))
			}
			require.Greater(t, queries.Load(), before)
		})
	}
}
