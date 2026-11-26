package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// errorCountCase is a request that fails, and what its progress ends at.
type errorCountCase struct {
	name    string
	request *httpprotocol.Request
	// input is the target, or the test server's URL when empty.
	input string
	// beforeSend closes the dialers the request needs to get its client, so
	// it fails before anything is sent.
	beforeSend bool
	// requests is how many requests count as processed.
	requests int64
	// errors is how many errors the failures add up to.
	errors int64
}

// errorCountCases lists requests of the sequential, parallel and race paths
// that fail while they are sent or before. Each failed request counts as one
// error and one processed request (#8202).
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func errorCountCases(refused string) []errorCountCase {
	return []errorCountCase{
		{
			name:     "refused",
			request:  &httpprotocol.Request{ID: "errors-refused", Method: methodGet(), Path: []string{skipPathA}},
			input:    "http://" + refused,
			requests: 1, errors: 1,
		},
		{
			name: "refused twice",
			request: &httpprotocol.Request{
				ID: "errors-refused-twice", Method: methodGet(), Path: []string{skipPathA, skipPathB},
			},
			input:    "http://" + refused,
			requests: 2, errors: 2,
		},
		{
			name: "refused in parallel",
			request: &httpprotocol.Request{
				ID: "errors-parallel", Method: methodGet(), Path: []string{skipPathPayload}, Threads: 2,
				Payloads: map[string]any{"v": []string{"1", "2"}},
			},
			input:    "http://" + refused,
			requests: 2, errors: 2,
		},
		{
			name: "refused in a race",
			request: &httpprotocol.Request{
				ID: "errors-race", Method: methodGet(), Path: []string{skipPathN}, Race: true, RaceNumberRequests: 2,
			},
			input:    "http://" + refused,
			requests: 2, errors: 2,
		},
		{
			name: "fails before it is sent",
			request: &httpprotocol.Request{
				ID: "errors-unsent", Method: methodGet(), Path: []string{skipPathA},
			},
			beforeSend: true,
			requests:   1, errors: 1,
		},
		{
			name: "fails before it is sent in parallel",
			request: &httpprotocol.Request{
				ID: "errors-unsent-parallel", Method: methodGet(), Path: []string{skipPathPayload}, Threads: 2,
				Payloads: map[string]any{"v": []string{"1", "2"}},
			},
			beforeSend: true,
			requests:   2, errors: 2,
		},
	}
}

// A failed request adds one to the errors and one to the processed requests
// (#8202). The progress display adds both when the same failure is counted
// as an error and again as a failed request.
//
//nolint:paralleltest // testutils.Init state is shared
func TestFailedRequestCountsOneError(t *testing.T) {
	refused := closedAddress(t)

	for _, test := range errorCountCases(refused) {
		t.Run(test.name, func(t *testing.T) {
			progress := compileWithCache(t, test.request, newDownHostErrorsCache(false))

			if test.beforeSend {
				protocolstate.Close(t.Name())
			}

			input := test.input
			if input == "" {
				server := httptest.NewServer(http.NotFoundHandler())
				t.Cleanup(server.Close)

				input = server.URL
			}

			_, err := executeSkippable(test.request, input)

			require.Error(t, err)

			if test.beforeSend {
				require.ErrorContains(t, err, "dialers not initialized")
			}

			require.Equal(t, test.requests, progress.requests.Load(), "requests processed")
			require.Equal(t, test.errors, progress.errors.Load(), "errors counted")
		})
	}
}
