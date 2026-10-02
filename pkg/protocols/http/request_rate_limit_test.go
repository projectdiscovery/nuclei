package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

func TestPerHostRateLimitHonorsRequestContextCancellation(t *testing.T) {
	options := *testutils.DefaultOptions
	options.ExecutionId = t.Name()
	options.PerHostRateLimit = true
	options.PerHostRateLimitPoolSize = -1
	options.RateLimit = 1
	options.RateLimitDuration = 2 * time.Second
	options.RestrictLocalNetworkAccess = false
	testutils.Init(&options)
	t.Cleanup(func() { testutils.Cleanup(&options) })

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(writer, "ok")
	}))
	defer server.Close()

	request := &Request{
		ID:     "per-host-rate-limit-cancellation",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}/"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"ok"},
		}}},
	}
	executerOptions := testutils.NewMockExecuterOptions(&options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOptions))

	execute := func(ctx context.Context) error {
		return request.ExecuteWithResults(
			contextargs.NewWithInput(ctx, server.URL),
			make(output.InternalEvent),
			make(output.InternalEvent),
			func(*output.InternalWrappedEvent) {},
		)
	}
	require.NoError(t, execute(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- execute(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancelledAt := time.Now()
	cancel()

	err := <-result
	cancellationDelay := time.Since(cancelledAt)
	t.Logf("request returned %s after its context was cancelled", cancellationDelay.Round(time.Millisecond))
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, cancellationDelay, 250*time.Millisecond)
}
