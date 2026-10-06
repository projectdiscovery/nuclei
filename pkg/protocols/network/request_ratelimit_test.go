package network

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestNetworkRequestsTakeFromRateLimiter(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-rate-limit"})
	executerOpts.RateLimiter.Stop()
	executerOpts.RateLimiter = ratelimit.New(context.Background(), 1, 300*time.Millisecond)
	t.Cleanup(executerOpts.RateLimiter.Stop)

	request := &Request{ID: "network-rate-limit", Address: []string{listener.Addr().String()}, ReadSize: 2}
	require.NoError(t, request.Compile(executerOpts))

	start := time.Now()
	for range 4 {
		input := contextargs.NewWithInput(context.Background(), listener.Addr().String())
		require.NoError(t, request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {}))
	}
	// 4 requests at 1 per 300ms cannot finish in under ~900ms when limited
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}
