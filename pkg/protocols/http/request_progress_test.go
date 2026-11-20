package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
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
