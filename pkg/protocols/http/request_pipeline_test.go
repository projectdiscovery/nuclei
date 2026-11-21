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

// countingServer serves skipOK, and counts the requests it gets and the
// connections they arrive on.
type countingServer struct {
	*httptest.Server

	requests    atomic.Int32
	connections atomic.Int32
}

// newCountingServer starts a countingServer, with TLS when useTLS is set.
//
//nolint:exhaustruct,exhaustruct_v5 // the counters start at zero
func newCountingServer(t *testing.T, useTLS bool) *countingServer {
	t.Helper()

	server := &countingServer{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		server.requests.Add(1)

		_, _ = io.WriteString(writer, skipOK)
	})

	server.Server = httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			server.connections.Add(1)
		}
	}

	if useTLS {
		server.StartTLS()
	} else {
		server.Start()
	}

	t.Cleanup(server.Close)

	return server
}

// A pipelined request goes to the address of its URL, not to the target's, and
// the block keeps one connection to each address (#8225).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineSendsToAddressOfItsURL(t *testing.T) {
	target, other := newCountingServer(t, false), newCountingServer(t, false)

	request := pipelined("pipe-other-address", map[string]any{"v": numberedPayloads(3)},
		"http://{{Host}}:"+serverPort(t, other.Server)+"/other?x={{v}}", skipPathPayload)
	request.Operators = matchStatusOK()
	progress := compileWithCache(t, request, newDownHostErrorsCache(false))

	events, err := executeSkippable(request, target.URL)

	require.NoError(t, err)
	require.Equal(t, 6, events)
	require.EqualValues(t, 3, other.requests.Load(), "requests to the other address")
	require.EqualValues(t, 1, other.connections.Load(), "connections to the other address")
	require.EqualValues(t, 3, target.requests.Load(), "requests to the target")
	require.EqualValues(t, 1, target.connections.Load(), "connections to the target")
	require.EqualValues(t, 6, progress.requests.Load(), "requests processed")
}

// A pipelined request to a target without a port dials the port of its scheme,
// as a request that is not pipelined does (#8213). Nothing listens on 80 or
// 443 here, so the dial fails, and its error names the address. The test skips
// where something does listen.
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineDialsDefaultPort(t *testing.T) {
	for scheme, port := range map[string]string{"http": "80", "https": "443"} {
		t.Run(scheme, func(t *testing.T) {
			request := pipelined("pipe-default-port-"+scheme, nil, "{{BaseURL}}/x")
			compileWithCache(t, request, newDownHostErrorsCache(false))

			_, err := executeSkippable(request, scheme+"://127.0.0.1")
			if err == nil {
				t.Skipf("something answers on 127.0.0.1:%s", port)
			}

			require.NotContains(t, err.Error(), "port was not specified")
			require.Contains(t, err.Error(), "127.0.0.1:"+port, "the address that was dialed")
		})
	}
}

// A raw pipelined request goes to the address and scheme of its own URL, which
// a @Host annotation sets, not to the target's (#8225).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestPipelineRawSendsToAddressOfItsURL(t *testing.T) {
	tests := []struct {
		name   string
		useTLS bool
		unsafe bool
		// schemeless makes the annotated server the target, and names it
		// without a scheme, so the input does not say it speaks TLS.
		schemeless bool
	}{
		{name: "unsafe", unsafe: true},
		{name: "safe"},
		{name: "unsafe to TLS from plain target", useTLS: true, unsafe: true},
		{name: "safe to TLS from plain target", useTLS: true},
		{name: "unsafe to TLS from scheme-less target", useTLS: true, unsafe: true, schemeless: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, other := newCountingServer(t, false), newCountingServer(t, test.useTLS)
			address := other.Listener.Addr().String()
			scheme := "http"

			if test.useTLS {
				scheme = "https"
			}

			request := pipelined("pipe-raw-address", nil)
			request.Path, request.Unsafe = nil, test.unsafe
			request.Raw = []string{"@Host: " + scheme + "://" + address + "\nGET /raw HTTP/1.1\nHost: " + address +
				"\nConnection: keep-alive\n\n"}
			compileWithCache(t, request, newDownHostErrorsCache(false))

			input := target.URL
			if test.schemeless {
				input, target = address, other
			}

			_, err := executeSkippable(request, input)

			require.NoError(t, err)
			require.EqualValues(t, 1, other.requests.Load(), "requests to the annotated address")

			if !test.schemeless {
				require.Zero(t, target.requests.Load(), "requests to the target")
			}
		})
	}
}

// The target's own address is down, but a request to another port of the same
// host is not, so the block sends it (#8201).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineRequestsToOtherPortAreSent(t *testing.T) {
	server, received := serverCountingHits(t)
	request := pipelined("pipe-other-port", map[string]any{"v": numberedPayloads(3)},
		"http://{{Host}}:"+serverPort(t, server)+"/?x={{v}}")
	progress := compileWithCache(t, request, newDownHostErrorsCache(false, schemelessAddress))

	_, err := executeSkippable(request, "https://"+schemelessTarget)

	require.NoError(t, err)
	require.EqualValues(t, 3, received.Load(), "every request is sent")
	require.EqualValues(t, 3, progress.requests.Load(), "requests processed")
	require.Zero(t, progress.errors.Load())
}

// A down address skips only its own requests: the ones to the other address
// are sent, the skip is reported once the block ends, and each request counts
// once.
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineSkipDoesNotStopRequestsToOtherAddress(t *testing.T) {
	server, received := serverCountingHits(t)
	down := closedAddress(t)
	request := pipelined("pipe-skip-other-address", map[string]any{"v": numberedPayloads(2)},
		"http://"+down+"/?x={{v}}", "{{BaseURL}}/?x={{v}}")
	progress := compileWithCache(t, request, newDownHostErrorsCache(false, down))

	_, err := executeSkippable(request, server.URL)

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.EqualValues(t, 2, received.Load(), "the requests to the live server are sent")
	require.EqualValues(t, 4, progress.requests.Load(), "every request is processed once")
	require.Zero(t, progress.errors.Load(), "a skipped request does not count as an error")
}

// An address that fails while the block runs does not end it: the requests to
// the other address go on, and the failure is the error to report.
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineFailureDoesNotStopRequestsToOtherAddress(t *testing.T) {
	server, received := serverCountingHits(t)
	closed := closedAddress(t)
	request := pipelined("pipe-failure-other-address", map[string]any{"v": numberedPayloads(1)},
		"http://"+closed+"/?x={{v}}", "{{BaseURL}}/?x={{v}}")
	cache := newDownHostErrorsCache(true)
	progress := compileWithCache(t, request, cache)

	// Hold the second request back until the first one's failure has marked
	// its address, which is when a block that ends on a down address stops.
	progress.onRequest = func(count int64) {
		if count != 2 {
			return
		}

		deadline := time.Now().Add(10 * time.Second)

		for time.Now().Before(deadline) {
			cache.mu.Lock()
			down := cache.down[closed]
			cache.mu.Unlock()

			if down {
				time.Sleep(50 * time.Millisecond)

				return
			}

			time.Sleep(time.Millisecond)
		}

		t.Error("the first request did not mark its address")
	}

	_, err := executeSkippable(request, server.URL)

	require.Error(t, err)
	require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Contains(t, err.Error(), closed)
	require.EqualValues(t, 1, received.Load(), "the request to the live server is sent")
	require.EqualValues(t, 2, progress.requests.Load(), "every request is processed once")
}

// A pipeline client with a custom dialer gets no default port from rawhttp, so
// pipelineAddress gives the port of the scheme, and keeps a host with a single
// label, such as an intranet or Docker name (#8213, #8225).
func TestPipelineAddress(t *testing.T) {
	t.Parallel()

	const (
		secureHost = "https://example.com/x"
		secureWeb  = "https://web"
	)

	tests := map[string]string{
		"http://127.0.0.1:18214/pipe": "127.0.0.1:18214",
		"http://example.com/x":        "example.com:80",
		secureHost:                    "example.com:443",
		"http://example.com:8080/x":   "example.com:8080",
		"http://intranet/x":           "intranet:80",
		"http://intranet":             "intranet:80",
		secureWeb:                     "web:443",
		"http://[::1]/x":              "[::1]:80",
		"https://[::1]:8443/x":        "[::1]:8443",
		"127.0.0.1:9/x":               "127.0.0.1:9",
		"example.com/x":               "example.com:80",
		"":                            "",
	}

	for requestURL, want := range tests {
		t.Run(requestURL, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, want, httpprotocol.PipelineAddress(requestURL))
		})
	}
}
