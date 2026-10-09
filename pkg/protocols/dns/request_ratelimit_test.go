package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestDNSRateLimitUsesQuestionName(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn: listener,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			_ = w.WriteMsg(new(dns.Msg).SetReply(r))
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	t.Cleanup(func() { _ = server.Shutdown() })
	go func() { _ = server.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server did not start")
	}

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = 1
	options.RateLimitDuration = 300 * time.Millisecond
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "dns-question-rate-limit"})
	executerOpts.RateLimiter.Stop()
	executerOpts.RateLimiter = ratelimit.NewUnlimited(context.Background())
	t.Cleanup(executerOpts.RateLimiter.Stop)

	recursion := false
	request := &Request{
		ID:          "dns-question-rate-limit",
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     1,
		Recursion:   &recursion,
		Name:        "fixed.example",
		Resolvers:   []string{listener.LocalAddr().String()},
	}
	require.NoError(t, request.Compile(executerOpts))

	start := time.Now()
	for _, host := range []string{"a.example", "b.example", "c.example", "d.example"} {
		input := contextargs.NewWithInput(context.Background(), host)
		require.NoError(t, request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {}))
	}
	// The question name is the same for every input, so they share one limiter.
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}
