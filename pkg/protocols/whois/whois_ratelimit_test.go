package whois

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestWhoisRequestsTakeFromRateLimiter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"domain","ldhName":"example.com"}`))
	}))
	t.Cleanup(server.Close)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "whois-rate-limit"})
	executerOpts.RateLimiter.Stop()
	executerOpts.RateLimiter = ratelimit.New(context.Background(), 1, 300*time.Millisecond)
	t.Cleanup(executerOpts.RateLimiter.Stop)

	request := &Request{ID: "whois-rate-limit", Query: "example.com", Server: server.URL}
	require.NoError(t, request.Compile(executerOpts))

	start := time.Now()
	for range 4 {
		input := contextargs.NewWithInput(context.Background(), "example.com")
		require.NoError(t, request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {}))
	}
	// 4 queries at 1 per 300ms cannot finish in under ~900ms when limited
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}
