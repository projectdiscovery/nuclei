package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// A request that cannot be built fails the execution. The raw request below
// has no line break, so its build fails with a wrapped io.EOF, an error that
// looks like the end of the requests and still has to be returned.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestRequestBuildErrorIsReturned(t *testing.T) {
	tests := []struct {
		name    string
		request *httpprotocol.Request
	}{
		{
			name:    "sequential",
			request: &httpprotocol.Request{ID: "build-error-sequential", Raw: []string{"GET"}},
		},
		{
			name: "threaded",
			request: &httpprotocol.Request{
				ID: "build-error-threaded", Raw: []string{"GET"}, Threads: 2,
				Payloads: map[string]any{"v": []string{"1", "2"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, received := serverCountingHits(t)
			compileWithCache(t, test.request, newDownHostErrorsCache(false))

			events, err := executeSkippable(test.request, server.URL)

			require.ErrorIs(t, err, io.EOF)
			require.ErrorContains(t, err, "failed to parse raw request")
			require.Zero(t, events)
			require.Zero(t, received.Load(), "a request that cannot be built is not sent")
		})
	}
}
