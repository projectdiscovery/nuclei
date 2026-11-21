package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"github.com/projectdiscovery/ratelimit"
)

const (
	skipTestName = "test"
	// schemelessTarget has no scheme, so its own address is 127.0.0.1:80 while
	// its requests go to https, which is 127.0.0.1:443.
	schemelessTarget  = "127.0.0.1"
	schemelessAddress = "127.0.0.1:443"
	skipPathA         = "{{BaseURL}}/a"
	skipPathB         = "{{BaseURL}}/b"
	skipPathC         = "{{BaseURL}}/c"
	skipPathN         = "{{BaseURL}}/n"
	skipPathPayload   = "{{BaseURL}}/n?x={{v}}"
	skipOK            = "ok"
	// skipMessage is what the engine writes for a target it skips.
	skipMessage = "host was skipped as it was found unresponsive"
)

func methodGet() httpprotocol.HTTPMethodTypeHolder {
	return httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet}
}

// skipProgress counts what the progress display would show: requests that
// count as done, and errors.
type skipProgress struct {
	testutils.MockProgressClient

	requests atomic.Int64
	errors   atomic.Int64
	// onRequest, when set before the request runs, is called with the count
	// after each IncrementRequests.
	onRequest func(count int64)
}

func (p *skipProgress) IncrementRequests() {
	count := p.requests.Add(1)
	if p.onRequest != nil {
		p.onRequest(count)
	}
}

func (p *skipProgress) SetRequests(count uint64) {
	p.requests.Add(int64(count)) //nolint:gosec // test counters stay small
}

func (p *skipProgress) IncrementErrorsBy(count int64) { p.errors.Add(count) }

func (p *skipProgress) IncrementFailedRequestsBy(count int64) {
	p.requests.Add(count)
	p.errors.Add(count)
}

// downHostErrorsCache reports the addresses in down as unresponsive. With
// markOnError, an address that fails a request joins them, as it does once a
// host has failed enough times.
type downHostErrorsCache struct {
	mu          sync.Mutex
	down        map[string]bool
	markOnError bool
	// downAfter, when set, makes every address unresponsive once Check has
	// been called that many times, as another template can do mid-run.
	downAfter int32
	checks    atomic.Int32
	recorded  atomic.Int32
}

//nolint:exhaustruct,exhaustruct_v5 // the counters start at zero
func newDownHostErrorsCache(markOnError bool, addresses ...string) *downHostErrorsCache {
	cache := &downHostErrorsCache{down: map[string]bool{}, markOnError: markOnError}
	for _, address := range addresses {
		cache.down[address] = true
	}

	return cache
}

func (c *downHostErrorsCache) SetVerbose(bool) {}

func (c *downHostErrorsCache) Close() {}

func (c *downHostErrorsCache) Remove(*contextargs.Context) {
	c.recorded.Add(1)
}

func (c *downHostErrorsCache) MarkFailed(protoType string, ctx *contextargs.Context, err error) {
	c.MarkFailedOrRemove(protoType, ctx, err)
}

func (c *downHostErrorsCache) MarkFailedOrRemove(_ string, ctx *contextargs.Context, err error) {
	c.recorded.Add(1)

	if err == nil || !c.markOnError {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.down[ctx.MetaInput.Address()] = true
}

func (c *downHostErrorsCache) Check(_ string, ctx *contextargs.Context) bool {
	if c.downAfter > 0 && c.checks.Add(1) > c.downAfter {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.down[ctx.MetaInput.Address()]
}

func (c *downHostErrorsCache) IsPermanentErr(*contextargs.Context, error) bool { return false }

// compileWithCache compiles request with cache as its host errors cache and a
// progress that counts.
func compileWithCache(t *testing.T, request *httpprotocol.Request, cache *downHostErrorsCache) *skipProgress {
	t.Helper()

	return compileWithBudget(t, request, cache, nil)
}

// compileWithBudget is compileWithCache with budget as the request-body
// budget, unless it is nil.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func compileWithBudget(
	t *testing.T, request *httpprotocol.Request, cache *downHostErrorsCache, budget *httpbody.Budget,
) *skipProgress {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: skipTestName},
	})
	t.Cleanup(executerOpts.RateLimiter.Stop)

	progress := &skipProgress{}
	executerOpts.Progress = progress
	executerOpts.HostErrorsCache = cache

	if budget != nil {
		executerOpts.RequestBodyBudget = budget
	}

	require.NoError(t, request.Compile(executerOpts))

	return progress
}

// executeSkippable runs request on input and returns the events it produced
// and its error.
func executeSkippable(request *httpprotocol.Request, input string) (int, error) {
	var count atomic.Int32

	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), input),
		make(output.InternalEvent), make(output.InternalEvent),
		func(*output.InternalWrappedEvent) { count.Add(1) })

	return int(count.Load()), err
}

// closedAddress returns an address nothing listens on.
func closedAddress(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	return address
}

// serverCountingHits serves skipOK and counts the requests it gets.
func serverCountingHits(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)

		_, _ = fmt.Fprint(w, skipOK)
	}))
	t.Cleanup(server.Close)

	return server, &received
}

// skipCase is a request that one of the execution paths stops before it is sent.
type skipCase struct {
	name    string
	request *httpprotocol.Request
	input   string
	address string
}

// skipCases lists the paths of an HTTP request: each of them has its own
// check for an unresponsive address.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func skipCases() []skipCase {
	payloads := map[string]any{"v": []string{"1", "2", "3"}}

	return []skipCase{
		{
			name:    "sequential",
			request: &httpprotocol.Request{ID: "skip-sequential", Method: methodGet(), Path: []string{skipPathA, skipPathB}},
			input:   schemelessTarget,
			address: schemelessAddress,
		},
		{
			name: "parallel",
			request: &httpprotocol.Request{
				ID: "skip-parallel", Method: methodGet(), Path: []string{skipPathPayload}, Threads: 2, Payloads: payloads,
			},
			input:   schemelessTarget,
			address: schemelessAddress,
		},
		{
			name: "race",
			request: &httpprotocol.Request{
				ID: "skip-race", Method: methodGet(), Path: []string{skipPathN}, Race: true, RaceNumberRequests: 2,
			},
			input:   schemelessTarget,
			address: schemelessAddress,
		},
		{
			name: "pipeline",
			request: &httpprotocol.Request{
				ID: "skip-pipeline", Method: methodGet(), Path: []string{skipPathA, skipPathB}, Pipeline: true,
			},
			input:   schemelessTarget,
			address: schemelessAddress,
		},
		{
			name: "fuzzing",
			request: &httpprotocol.Request{ID: "skip-fuzzing", Fuzzing: []*fuzz.Rule{{
				Part: "query", Type: "postfix", Mode: "single", Fuzz: fuzz.SliceOrMapSlice{Value: []string{"x1", "x2"}},
			}}},
			input:   "http://127.0.0.1:1/?a=1",
			address: "127.0.0.1:1",
		},
	}
}

// A request that is not sent because its address is unresponsive reports
// that, whichever path stops it, and does not count as an error (#8196). The
// requests of most cases go to an address other than the target's own.
//
//nolint:paralleltest // testutils.Init state is shared
func TestSkippedRequestsReportUnresponsiveAddress(t *testing.T) {
	for _, test := range skipCases() {
		t.Run(test.name, func(t *testing.T) {
			cache := newDownHostErrorsCache(false, test.address)
			progress := compileWithCache(t, test.request, cache)

			events, err := executeSkippable(test.request, test.input)

			require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			require.EqualError(t, err, skipMessage)
			require.Zero(t, events, "no request is sent, so there is no event")
			require.Zero(t, cache.recorded.Load(), "a skip is not a request outcome the cache records")
			require.Zero(t, progress.errors.Load(), "a skipped request does not count as an error")
		})
	}
}

// A skipped request does not end the block, since the requests after it can go
// to another address. The skip is reported with the requests that were sent,
// and every request counts as processed once (#7838), but not as an error.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestSkipAfterSentRequestReportsSkip(t *testing.T) {
	server, received := serverCountingHits(t)
	other := closedAddress(t)
	request := &httpprotocol.Request{
		ID:     "skip-after-sent",
		Method: methodGet(),
		Path:   []string{skipPathA, "http://" + other + "/b", skipPathC},
	}
	progress := compileWithCache(t, request, newDownHostErrorsCache(false, other))

	_, err := executeSkippable(request, server.URL)

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.EqualValues(t, 2, received.Load(), "the requests around the skipped one are sent")
	require.EqualValues(t, 3, progress.requests.Load(), "every request is processed")
	require.Zero(t, progress.errors.Load())
}

// A request skipped for its address is not sent, so it does not take a
// rate-limit token that every other template shares. The limiter here has one
// token for an hour, and the first request takes it: a skipped request that
// waited for another would run out the deadline.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestSkippedRequestTakesNoRateLimitToken(t *testing.T) {
	server, received := serverCountingHits(t)
	down := closedAddress(t)
	request := &httpprotocol.Request{
		ID:     "skip-takes-no-token",
		Method: methodGet(),
		Path:   []string{skipPathA, "http://" + down + "/1", "http://" + down + "/2", "http://" + down + "/3"},
	}

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: skipTestName},
	})
	progress := &skipProgress{}
	executerOpts.Progress = progress
	executerOpts.HostErrorsCache = newDownHostErrorsCache(false, down)
	require.NoError(t, request.Compile(executerOpts))

	executerOpts.RateLimiter.Stop()

	executerOpts.RateLimiter = ratelimit.New(t.Context(), 1, time.Hour)
	t.Cleanup(executerOpts.RateLimiter.Stop)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err := request.ExecuteWithResults(contextargs.NewWithInput(ctx, server.URL),
		make(output.InternalEvent), make(output.InternalEvent), func(*output.InternalWrappedEvent) {})

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.EqualValues(t, 1, received.Load())
	require.EqualValues(t, 4, progress.requests.Load(), "every request is processed")
	require.Zero(t, progress.errors.Load())
}

// serverPort returns the port server listens on.
func serverPort(t *testing.T, server *httptest.Server) string {
	t.Helper()

	address, err := url.Parse(server.URL)
	require.NoError(t, err)

	return address.Port()
}

// The target's own address is down, but a request to another port of the same
// host is not. The skip of the first requests does not stop the one after
// them (#8201).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestSkipDoesNotStopSequentialRequestToOtherPort(t *testing.T) {
	server, received := serverCountingHits(t)
	cache := newDownHostErrorsCache(false, schemelessAddress)
	request := &httpprotocol.Request{
		ID:     "skip-other-port-sequential",
		Method: methodGet(),
		Path:   []string{skipPathA, skipPathB, "http://{{Host}}:" + serverPort(t, server) + "/"},
	}
	progress := compileWithCache(t, request, cache)

	events, err := executeSkippable(request, "https://"+schemelessTarget)

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Equal(t, 1, events)
	require.EqualValues(t, 1, received.Load(), "the request to the open port is sent")
	require.EqualValues(t, 3, progress.requests.Load(), "every request is processed")
	require.Zero(t, progress.errors.Load(), "a skipped request does not count as an error")
	require.EqualValues(t, 1, cache.recorded.Load(), "only the sent request is recorded")
}

// The payload requests go to an open port of the target while the target's own
// port is down, as in a template that probes another port (#8201).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestParallelRequestsToOtherPortAreSent(t *testing.T) {
	server, received := serverCountingHits(t)
	request := &httpprotocol.Request{
		ID:       "other-port-parallel",
		Method:   methodGet(),
		Path:     []string{"http://{{Host}}:" + serverPort(t, server) + "/?x={{v}}"},
		Threads:  2,
		Payloads: map[string]any{"v": []string{"1", "2", "3"}},
	}
	progress := compileWithCache(t, request, newDownHostErrorsCache(false, schemelessAddress))

	_, err := executeSkippable(request, "https://"+schemelessTarget)

	require.NoError(t, err)
	require.EqualValues(t, 3, received.Load(), "every payload request is sent")
	require.EqualValues(t, 3, progress.requests.Load())
	require.Zero(t, progress.errors.Load())
}

// A down address skips only its own requests: the ones to the other address
// are sent, and the skip is reported once the block ends.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestParallelSkipDoesNotStopRequestsToOtherAddress(t *testing.T) {
	server, received := serverCountingHits(t)
	down := closedAddress(t)
	request := &httpprotocol.Request{
		ID:       "skip-other-address-parallel",
		Method:   methodGet(),
		Path:     []string{"http://" + down + "/?x={{v}}", "{{BaseURL}}/?x={{v}}"},
		Threads:  2,
		Payloads: map[string]any{"v": []string{"1", "2"}},
	}
	progress := compileWithCache(t, request, newDownHostErrorsCache(false, down))

	_, err := executeSkippable(request, server.URL)

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.EqualValues(t, 2, received.Load(), "the requests to the live server are sent")
	require.EqualValues(t, 4, progress.requests.Load(), "every request is processed once")
	require.Zero(t, progress.errors.Load(), "a skipped request does not count as an error")
}

// An address that fails while the block runs skips its later requests, and the
// requests to the other address go on. The failure is the error to report, not
// the skips after it.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestParallelFailureDoesNotStopRequestsToOtherAddress(t *testing.T) {
	server, received := serverCountingHits(t)
	closed := closedAddress(t)
	request := &httpprotocol.Request{
		ID:     "failure-other-address-parallel",
		Method: methodGet(),
		Path:   []string{"http://" + closed + "/?x={{v}}", "{{BaseURL}}/?x={{v}}"},
		// one worker, so the first failure marks the address before the next one runs
		Threads:  1,
		Payloads: map[string]any{"v": []string{"1", "2", "3"}},
	}
	progress := compileWithCache(t, request, newDownHostErrorsCache(true))

	_, err := executeSkippable(request, server.URL)

	require.Error(t, err)
	require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Contains(t, err.Error(), closed)
	require.EqualValues(t, 3, received.Load(), "the requests to the live server are sent")
	require.EqualValues(t, 1, progress.errors.Load(), "only the request that failed counts as an error")
	require.EqualValues(t, 6, progress.requests.Load(), "every request is processed once")
}

// The address can turn unresponsive while the requests run, as another
// template can mark it. The requests that are left report the skip, wherever
// the execution notices it.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestSkipDuringExecutionReportsUnresponsiveAddress(t *testing.T) {
	const requests = 30

	payloads := make([]string, requests)
	for i := range payloads {
		payloads[i] = strconv.Itoa(i)
	}

	tests := []struct {
		name    string
		request *httpprotocol.Request
	}{
		{
			name: "parallel",
			request: &httpprotocol.Request{
				ID: "skip-during-parallel", Method: methodGet(), Path: []string{skipPathPayload},
				Threads: 2, Payloads: map[string]any{"v": payloads},
			},
		},
		{
			name: "race",
			request: &httpprotocol.Request{
				ID: "skip-during-race", Method: methodGet(), Path: []string{skipPathN},
				Race: true, RaceNumberRequests: requests,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, received := serverCountingHits(t)
			cache := newDownHostErrorsCache(false)
			cache.downAfter = 5
			progress := compileWithCache(t, test.request, cache)

			_, err := executeSkippable(test.request, server.URL)

			require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			require.Less(t, received.Load(), int32(requests), "the requests after the skip are not sent")
			require.Zero(t, progress.errors.Load())
		})
	}
}

// A request error the execution already hit is the error to report, not the
// skip of the requests after it.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestRequestErrorWinsOverSkip(t *testing.T) {
	closed := closedAddress(t)

	t.Run("sequential", func(t *testing.T) {
		request := &httpprotocol.Request{
			ID:     "error-wins-sequential",
			Method: methodGet(),
			Path:   []string{"http://" + closed + "/a", "http://" + closed + "/b"},
		}
		compileWithCache(t, request, newDownHostErrorsCache(true))

		_, err := executeSkippable(request, "http://"+closed)

		require.Error(t, err)
		require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
		require.Contains(t, err.Error(), closed)
	})

	t.Run("parallel", func(t *testing.T) {
		request := &httpprotocol.Request{
			ID:     "error-wins-parallel",
			Method: methodGet(),
			Path:   []string{"http://" + closed + "/n?x={{v}}"},
			// one worker, so the first failure marks the address before the next payload
			Threads:  1,
			Payloads: map[string]any{"v": []string{"1", "2", "3", "4"}},
		}
		compileWithCache(t, request, newDownHostErrorsCache(true))

		_, err := executeSkippable(request, "http://"+closed)

		require.Error(t, err)
		require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
		require.Contains(t, err.Error(), closed)
	})
}
