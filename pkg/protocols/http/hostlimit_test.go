package http

import (
	"context"
	nethttp "net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostlimit"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Time spent queued for an endpoint slot is added back to the request deadline,
// so a queued request cannot time out before it is sent.
func TestAdmitExtendsDeadlineByQueueTime(t *testing.T) {
	limit := hostlimit.New(hostlimit.Config{Initial: 1, Min: 1, Max: 1})
	r := &Request{options: &protocols.ExecutorOptions{Options: &types.Options{}, HostLimit: limit}}

	held, _ := limit.Acquire(context.Background(), "example.com:80")
	go func() { time.Sleep(150 * time.Millisecond); held.Release(hostlimit.Outcome{}) }()

	reqCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rr, err := retryablehttp.NewRequestWithContext(reqCtx, nethttp.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	gen := &generatedRequest{request: rr, original: &Request{}}
	before, _ := rr.Context().Deadline()

	ticket, release, err := r.admitToEndpoint(context.Background(), gen)
	if err != nil {
		t.Fatalf("admission must not fail on the request deadline: %v", err)
	}
	defer release()
	defer ticket.Release(hostlimit.Outcome{})

	after, ok := gen.request.Context().Deadline()
	if !ok || !after.After(before.Add(100*time.Millisecond)) {
		t.Fatalf("deadline not extended by the queue time: before=%v after=%v", before, after)
	}
	if gen.request.Context().Err() != nil {
		t.Fatal("the request context must still be live after admission")
	}
}

// Without adaptive concurrency admission is a no-op.
func TestAdmitWithoutLimiter(t *testing.T) {
	r := &Request{options: &protocols.ExecutorOptions{Options: &types.Options{}}}
	rr, _ := retryablehttp.NewRequest(nethttp.MethodGet, "http://example.com/", nil)
	ticket, release, err := r.admitToEndpoint(context.Background(), &generatedRequest{request: rr})
	if err != nil || ticket != nil {
		t.Fatalf("expected a no-op, got ticket=%v err=%v", ticket, err)
	}
	release()
}
