package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// serverMissingPath serves 404 for /miss and 200 for any other path, and
// counts the requests it gets.
func serverMissingPath(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		received.Add(1)

		if req.URL.Path == "/miss" {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = fmt.Fprint(writer, skipOK)
	}))
	t.Cleanup(server.Close)

	return server, &received
}

// matchStatusOK matches a response with status 200.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func matchStatusOK() operators.Operators {
	return operators.Operators{
		Matchers: []*matchers.Matcher{{
			Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
			Status: []int{http.StatusOK},
		}},
	}
}

// progressCase is a request that stops, and what its progress ends at.
type progressCase struct {
	name    string
	request *httpprotocol.Request
	// input is the target, or the test server's URL when empty.
	input string
	// sent is how many requests reach the server.
	sent int32
	// total is the number of requests the request has.
	total int64
	// wantErr is whether the execution returns an error.
	wantErr bool
}

// stopAtFirstMatch is a request for paths that stops at the first response
// with status 200.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func stopAtFirstMatch(id string, paths ...string) *httpprotocol.Request {
	return &httpprotocol.Request{
		ID: id, Method: methodGet(), Path: paths, Operators: matchStatusOK(), StopAtFirstMatch: true,
	}
}

// progressCases lists the ways a sequential execution ends, or does not,
// before its last request.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func progressCases() []progressCase {
	const (
		missPath  = "{{BaseURL}}/miss"
		onceToken = "@once\nGET /token HTTP/1.1\nHost: {{Hostname}}"
		rawUse    = "GET /use/{{v}} HTTP/1.1\nHost: {{Hostname}}"
	)

	withPayloads := stopAtFirstMatch("total-payloads", skipPathPayload, skipPathPayload+"&y=1")
	withPayloads.Payloads = map[string]any{"v": []string{"1", "2", "3"}}

	withOnce := stopAtFirstMatch("total-once")
	withOnce.Path, withOnce.Raw = nil, []string{onceToken, rawUse}
	withOnce.Payloads = map[string]any{"v": []string{"1", "2"}}

	return []progressCase{
		{
			name:    "first of two matches",
			request: stopAtFirstMatch("total-first-of-two", skipPathA, skipPathB),
			sent:    1, total: 2,
		},
		{
			name:    "second of three matches",
			request: stopAtFirstMatch("total-second-of-three", missPath, skipPathA, skipPathB),
			sent:    2, total: 3,
		},
		{
			name:    "last of two matches",
			request: stopAtFirstMatch("total-last-of-two", missPath, skipPathA),
			sent:    2, total: 2,
		},
		{
			name:    "no match",
			request: stopAtFirstMatch("total-no-match", missPath, missPath),
			sent:    2, total: 2,
		},
		{name: "first of two paths with payloads matches", request: withPayloads, sent: 1, total: 6},
		{name: "once request matches", request: withOnce, sent: 1, total: 3},
		{
			name:    "request that is not built",
			request: stopAtFirstMatch("total-not-built", skipPathA, skipPathB),
			input:   "://invalid",
			total:   2,
			wantErr: true,
		},
	}
}

// The requests that a stop leaves unsent count as processed (#7838), so the
// count ends at the total whichever request stops the execution (#8204).
//
//nolint:paralleltest // testutils.Init state is shared
func TestProcessedRequestsEndAtTotal(t *testing.T) {
	for _, test := range progressCases() {
		t.Run(test.name, func(t *testing.T) {
			server, received := serverMissingPath(t)
			progress := compileWithCache(t, test.request, newDownHostErrorsCache(false))

			input := test.input
			if input == "" {
				input = server.URL
			}

			_, err := executeSkippable(test.request, input)

			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.sent, received.Load(), "requests sent")
			require.Equal(t, test.total, progress.requests.Load(), "requests processed")
			require.Zero(t, progress.errors.Load(), "requests counted as errors")
		})
	}
}

// numberedPayloads returns the payloads "1" to "count".
func numberedPayloads(count int) []string {
	payloads := make([]string, count)
	for i := range payloads {
		payloads[i] = strconv.Itoa(i + 1)
	}

	return payloads
}

const (
	// buildPath makes a request fail to build for a payload that is not a number.
	buildPath = "{{BaseURL}}/?n={{to_number(p)}}"
	// buildMessage is what the engine writes for a request that fails to build.
	buildMessage = "could not be converted"
)

// unbuildablePayloads returns 10 payloads whose 4th fails buildPath.
func unbuildablePayloads() []string {
	payloads := numberedPayloads(10)
	payloads[3] = "x"

	return payloads
}

// pipelined returns a request that sends its paths over a pipeline. Without a
// keep-alive header, the pipeline asks the server to close the connection.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func pipelined(id string, payloads map[string]any, paths ...string) *httpprotocol.Request {
	return &httpprotocol.Request{
		ID: id, Method: methodGet(), Path: paths, Pipeline: true, Payloads: payloads,
		Headers: map[string]string{"Connection": "keep-alive"},
	}
}

// threadedCase is a payload block that ends early or completely, and what its
// progress ends at.
type threadedCase struct {
	name    string
	request *httpprotocol.Request
	// input is the target, or the test server's URL when empty.
	input string
	// down marks the test server's address as unresponsive.
	down bool
	// total is the number of requests the block has.
	total int64
	// events is how many results the block reports.
	events int
	// wantErr is a part of the error the execution returns, if it returns one.
	wantErr string
}

// threadedCases lists the ways a threaded or pipelined block ends before it
// has taken its last request, and the two ways it ends after.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func threadedCases() []threadedCase {
	numbers := func(count int) map[string]any { return map[string]any{"v": numberedPayloads(count)} }

	parStop := &httpprotocol.Request{
		ID: "par-stop", Method: methodGet(), Path: []string{skipPathPayload}, Threads: 1, Payloads: numbers(10),
		Operators: matchStatusOK(), StopAtFirstMatch: true,
	}
	parDown := &httpprotocol.Request{
		ID: "par-down", Method: methodGet(), Path: []string{skipPathPayload}, Threads: 2, Payloads: numbers(10),
	}
	parBuild := &httpprotocol.Request{
		ID: "par-build", Method: methodGet(), Path: []string{buildPath}, Threads: 2,
		Payloads: map[string]any{"p": unbuildablePayloads()}, Operators: matchStatusOK(),
	}
	parAll := &httpprotocol.Request{
		ID: "par-all", Method: methodGet(), Path: []string{skipPathPayload, skipPathPayload + "&y=1"}, Threads: 2,
		Payloads: numbers(2), Operators: matchStatusOK(),
	}

	pipeStop := pipelined("pipe-stop", numbers(200), skipPathPayload)
	pipeStop.PipelineRequestsPerConnection = 150
	pipeStop.Operators, pipeStop.StopAtFirstMatch = matchStatusOK(), true

	pipeAll := pipelined("pipe-all", numbers(2), skipPathPayload, skipPathPayload+"&y=1")
	pipeAll.Operators = matchStatusOK()

	return []threadedCase{
		{name: "parallel stops at first match", request: parStop, total: 10, events: 1},
		{
			name: "parallel target unresponsive", request: parDown, down: true, total: 10, wantErr: skipMessage,
		},
		{
			name: "parallel request not built", request: parBuild, total: 10, events: 3, wantErr: buildMessage,
		},
		{name: "pipeline stops at first match", request: pipeStop, total: 200, events: 1},
		{
			name: "pipeline target unresponsive", request: pipelined("pipe-down", numbers(10), skipPathPayload),
			down: true, total: 10, wantErr: skipMessage,
		},
		{
			name: "pipeline input does not parse", request: pipelined("pipe-parse", numbers(3), skipPathPayload),
			input: "://invalid", total: 3, wantErr: "invalid scheme",
		},
		{name: "parallel ends after its last request", request: parAll, total: 4, events: 4},
		{name: "pipeline ends after its last request", request: pipeAll, total: 4, events: 4},
	}
}

// A threaded or pipelined block counts each of its requests once, whether the
// block sends it, stops before it, skips it, or fails to build it (#8224).
//
//nolint:paralleltest // testutils.Init state is shared
func TestThreadedRequestsEndAtTotal(t *testing.T) {
	for _, test := range threadedCases() {
		t.Run(test.name, func(t *testing.T) {
			server, _ := serverCountingHits(t)

			var down []string
			if test.down {
				down = append(down, server.Listener.Addr().String())
			}

			progress := compileWithCache(t, test.request, newDownHostErrorsCache(false, down...))

			input := test.input
			if input == "" {
				input = server.URL
			}

			events, err := executeSkippable(test.request, input)

			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}

			require.Equal(t, test.events, events, "results reported")
			require.Equal(t, test.total, progress.requests.Load(), "requests processed")
			require.Zero(t, progress.errors.Load(), "requests counted as errors")
		})
	}
}

// A pipelined block that fails to build a request still waits for the requests
// it sent, so their results are reported before it returns (#8243).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineReportsRequestsSentBeforeBuildError(t *testing.T) {
	// The server answers nothing until release closes, as a server that is
	// slow to answer the first request does.
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release

		_, _ = fmt.Fprint(w, skipOK)
	}))
	t.Cleanup(server.Close)
	// It runs before server.Close, which waits for the handlers to return.
	t.Cleanup(releaseOnce)

	request := pipelined("pipe-build", map[string]any{"p": unbuildablePayloads()}, buildPath)
	request.Operators = matchStatusOK()
	progress := compileWithCache(t, request, newDownHostErrorsCache(false))

	type outcome struct {
		err    error
		events int32
	}

	var events atomic.Int32

	done := make(chan outcome, 1)

	go func() {
		err := request.ExecuteWithResults(contextargs.NewWithInput(t.Context(), server.URL),
			make(output.InternalEvent), make(output.InternalEvent),
			func(*output.InternalWrappedEvent) { events.Add(1) })
		done <- outcome{err: err, events: events.Load()}
	}()

	// A block that does not wait returns inside this time, with no results.
	// One that waits returns once the server answers.
	time.AfterFunc(200*time.Millisecond, releaseOnce)

	var got outcome

	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the block did not return")
	}

	require.ErrorContains(t, got.err, buildMessage)
	require.EqualValues(t, 3, got.events, "results reported before the block returns")
	require.EqualValues(t, 10, progress.requests.Load(), "requests processed")
	require.Zero(t, progress.errors.Load(), "requests counted as errors")
}
