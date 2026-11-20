package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
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
}

func (p *skipProgress) IncrementRequests() { p.requests.Add(1) }

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
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func compileWithCache(t *testing.T, request *httpprotocol.Request, cache *downHostErrorsCache) *skipProgress {
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

// The skip is reported with the requests sent before it. The requests it
// leaves unsent count as processed, as on a stop at the first match (#7838),
// but not as errors.
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
	require.EqualValues(t, 1, received.Load(), "only the first request is sent")
	require.EqualValues(t, 3, progress.requests.Load(), "every request is processed")
	require.Zero(t, progress.errors.Load())
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
