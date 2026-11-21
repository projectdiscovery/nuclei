package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
)

// holdingServer reads pipelined requests and answers each one only after
// release closes. It returns the address, a channel that receives once per
// request it has read, and release.
func holdingServer(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	// It runs before the listener closes, so the handler never blocks forever.
	t.Cleanup(releaseOnce)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)

		for {
			_, err := http.ReadRequest(reader)
			if err != nil {
				return
			}

			arrived <- struct{}{}

			<-release

			_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			if err != nil {
				return
			}
		}
	}()

	return listener.Addr().String(), arrived, releaseOnce
}

// A pipelined block whose input context is canceled while it sends waits for
// the requests it already sent, so no result reaches the callback after the
// block returns, as with threads (#8255).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineCancelWaitsForSentRequests(t *testing.T) {
	address, arrived, release := holdingServer(t)

	request := pipelined("pipe-cancel", map[string]any{"v": numberedPayloads(3)}, skipPathPayload)
	request.Operators = matchStatusOK()
	progress := compileWithCache(t, request, newDownHostErrorsCache(false))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// The loop counts a request when it takes it, so the second count comes
	// after the first request started. Once the server holds that request,
	// cancel, and answer it 200ms later.
	progress.onRequest = func(count int64) {
		if count != 2 {
			return
		}

		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Error("the server did not get the first request")
		}

		cancel()
		time.AfterFunc(200*time.Millisecond, release)
	}

	var events atomic.Int32

	err := request.ExecuteWithResults(contextargs.NewWithInput(ctx, "http://"+address),
		make(output.InternalEvent), make(output.InternalEvent),
		func(*output.InternalWrappedEvent) { events.Add(1) })

	require.ErrorIs(t, err, context.Canceled)
	// The loop took the second request but did not send it.
	require.EqualValues(t, 1, events.Load(), "results reported before the block returns")
}

// serverReadingBodies serves skipOK after it reads the request body, and counts
// the requests it gets.
func serverReadingBodies(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		received.Add(1)

		_, _ = io.WriteString(w, skipOK)
	}))
	t.Cleanup(server.Close)

	return server, &received
}

// pipelinedBudgetBlock returns a pipelined block that stops at its first
// match and sends 3 requests with a body that waits for the body budget.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func pipelinedBudgetBlock(id string) *httpprotocol.Request {
	return &httpprotocol.Request{
		ID: id, Pipeline: true, StopAtFirstMatch: true, Operators: matchStatusOK(),
		Payloads: map[string]any{"p": numberedPayloads(3)},
		Raw: []string{"POST /?p={{p}} HTTP/1.1\nHost: {{Hostname}}\nConnection: keep-alive\n" +
			"Content-Length: 1048576\n\n{{repeat(\"A\", 1048576)}}"},
	}
}

// A pipelined block that finds its first match ends there, although another
// block's request holds the body budget that the block's next request waits
// for (#8256).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineEndsAtFirstMatchWhileWaitingForBudget(t *testing.T) {
	const size = httpbody.MinBudgetedBody

	server, received := serverReadingBodies(t)
	request := pipelinedBudgetBlock("pipe-budget")
	budget := httpbody.NewBudget(size)
	compileWithBudget(t, request, newDownHostErrorsCache(false), budget)

	// Another block holds the whole budget, and queues its next request
	// ahead of the pipelined block's second one.
	releaseHeld, err := budget.Acquire(t.Context(), size)
	require.NoError(t, err)

	matched := make(chan struct{}, 8)
	done := make(chan error, 1)

	go func() {
		done <- request.ExecuteWithResults(contextargs.NewWithInput(t.Context(), server.URL),
			make(output.InternalEvent), make(output.InternalEvent),
			func(event *output.InternalWrappedEvent) {
				if event.HasOperatorResult() {
					matched <- struct{}{}
				}
			})
	}()

	// The first request is built and waits for the budget.
	time.Sleep(300 * time.Millisecond)

	next := make(chan func(), 1)

	go func() {
		release, err := budget.Acquire(t.Context(), size)
		if err == nil {
			next <- release
		}
	}()

	time.Sleep(300 * time.Millisecond)
	// The first request gets the budget, is sent and matches, and then the
	// other block's next request gets it.
	releaseHeld()

	var releaseNext func()

	select {
	case <-matched:
		releaseNext = sync.OnceFunc(<-next)
	case <-time.After(10 * time.Second):
		t.Fatal("the first request did not match")
	}

	// The block's second request now waits for budget that stays held.
	defer releaseNext()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		releaseNext()

		err := <-done
		t.Fatalf("the block waited for the budget after its first match, until it returned %v", err)
	}

	require.EqualValues(t, 1, received.Load(), "requests sent")
}

// A pipelined block that waits for body budget still returns the input's
// cancel as an error, though a stop-at-first-match handler that derives from
// the input also reports that cancel as a first match (#8256).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineCancelWhileWaitingForBudget(t *testing.T) {
	const size = httpbody.MinBudgetedBody

	server, received := serverCountingHits(t)
	request := pipelinedBudgetBlock("pipe-budget-cancel")
	budget := httpbody.NewBudget(size)
	compileWithBudget(t, request, newDownHostErrorsCache(false), budget)

	// Another block holds the whole budget, so the first request waits for it.
	releaseHeld, err := budget.Acquire(t.Context(), size)
	require.NoError(t, err)

	t.Cleanup(releaseHeld)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	input := contextargs.NewWithInput(ctx, server.URL)
	done := make(chan error, 1)

	go func() {
		done <- request.ExecuteWithResults(input,
			make(output.InternalEvent), make(output.InternalEvent), func(*output.InternalWrappedEvent) {})
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the block did not return after the cancel")
	}

	require.Zero(t, received.Load(), "requests sent")
}

// A pipelined block whose address another block marks unresponsive while it
// waits for budget still reports the skip, as it does when it waits for the
// budget to the end (#8256).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineSkipsUnresponsiveAddressDuringBudgetWait(t *testing.T) {
	arrived := make(chan struct{}, 4)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)

		arrived <- struct{}{}

		<-release

		_, _ = io.WriteString(writer, skipOK)
	}))
	t.Cleanup(server.Close)
	// It runs before server.Close, which waits for the handlers to return.
	t.Cleanup(releaseOnce)

	// Without stop-at-first-match, the only thing that cancels the handler
	// is the address going down.
	request := pipelinedBudgetBlock("pipe-budget-down")
	request.StopAtFirstMatch = false
	cache := newDownHostErrorsCache(false)
	compileWithBudget(t, request, cache, httpbody.NewBudget(httpbody.MinBudgetedBody))

	done := make(chan error, 1)

	go func() {
		done <- request.ExecuteWithResults(contextargs.NewWithInput(t.Context(), server.URL),
			make(output.InternalEvent), make(output.InternalEvent), func(*output.InternalWrappedEvent) {})
	}()

	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not get the first request")
	}

	// The second request waits for the budget that the first one holds. The
	// other block marks the address down before the first request succeeds.
	time.Sleep(300 * time.Millisecond)
	cache.mu.Lock()
	cache.down[server.Listener.Addr().String()] = true
	cache.mu.Unlock()
	releaseOnce()

	select {
	case err := <-done:
		require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	case <-time.After(10 * time.Second):
		t.Fatal("the block did not return")
	}
}
