package ssl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestSSLRequestsTakeFromRateLimiter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "https://")

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "ssl-rate-limit"})
	executerOpts.IsMultiProtocol = true
	executerOpts.RateLimiter.Stop()
	executerOpts.RateLimiter = ratelimit.New(context.Background(), 1, 300*time.Millisecond)
	t.Cleanup(executerOpts.RateLimiter.Stop)

	request := &Request{ID: "ssl-rate-limit", Address: "{{Hostname}}"}
	require.NoError(t, request.Compile(executerOpts))

	start := time.Now()
	for range 4 {
		input := contextargs.NewWithInput(context.Background(), address)
		require.NoError(t, request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {}))
	}
	// 4 handshakes at 1 per 300ms cannot finish in under ~900ms when limited
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}
