package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

type countingProgress struct {
	testutils.MockProgressClient
	total    atomic.Int64
	requests atomic.Int64
}

func (p *countingProgress) AddToTotal(delta int64) { p.total.Add(delta) }

func (p *countingProgress) IncrementRequests() { p.requests.Add(1) }

func TestFuzzingRequestsAreCountedInProgressTotal(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
	}))
	defer server.Close()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.DAST = true
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executorOptions := testutils.NewMockExecuterOptions(options, nil)
	t.Cleanup(executorOptions.RateLimiter.Stop)
	progress := &countingProgress{}
	executorOptions.Progress = progress
	request := &Request{Fuzzing: []*fuzz.Rule{
		{Part: "query", Type: "postfix", Mode: "single", Fuzz: fuzz.SliceOrMapSlice{Value: []string{"x1", "x2", "x3"}}},
	}}
	require.NoError(t, request.Compile(executorOptions))
	require.Zero(t, request.Requests())

	input := contextargs.NewWithInput(context.Background(), server.URL+"/?a=1&b=2")
	err := request.executeFuzzingRule(input, nil, func(*output.InternalWrappedEvent) {})
	require.NoError(t, err)

	require.EqualValues(t, 6, received.Load())
	require.EqualValues(t, 6, progress.requests.Load())
	require.EqualValues(t, 6, progress.total.Load())
}
