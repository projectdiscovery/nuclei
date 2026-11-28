package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// pipelinePath is one request per payload of a pipelined block.
const pipelinePath = "{{BaseURL}}/?p={{p}}"

// connectionRecorder serves "ok" and records the connections it accepts and
// the Connection header of each request. Like any HTTP/1.1 server, it closes a
// connection after a request that carries "Connection: close".
type connectionRecorder struct {
	connections atomic.Int32

	mu         sync.Mutex
	connection []string
}

//nolint:exhaustruct,exhaustruct_v5 // the recorder starts empty
func newConnectionRecorder(t *testing.T) (*httptest.Server, *connectionRecorder) {
	t.Helper()

	recorder := &connectionRecorder{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		recorder.connection = append(recorder.connection, r.Header.Get("Connection"))
		recorder.mu.Unlock()

		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			recorder.connections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	return server, recorder
}

// executePipelined compiles request as a pipelined block of payloads requests
// and runs it against target.
func executePipelined(t *testing.T, request *httpprotocol.Request, target string, payloads int) error {
	t.Helper()

	values := make([]string, payloads)
	for i := range values {
		values[i] = strconv.Itoa(i)
	}

	request.ID = "pipeline-connection"
	request.Pipeline = true
	request.PipelineConcurrentConnections = 1
	request.PipelineRequestsPerConnection = payloads
	request.Payloads = map[string]any{"p": values}

	compileWithCache(t, request, newDownHostErrorsCache(false))

	_, err := executeSkippable(request, target)

	return err
}

// A pipelined block sends its requests down one connection, so it must not
// tell the server to close that connection unless the template asks for it.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestPipelineKeepsConnectionOpen(t *testing.T) {
	const payloads = 10

	tests := []struct {
		name    string
		request *httpprotocol.Request
		// want is the Connection header the server sees on every request.
		want string
	}{
		{
			name:    "path",
			request: &httpprotocol.Request{Method: methodGet(), Path: []string{pipelinePath}},
		},
		{
			name:    "raw",
			request: &httpprotocol.Request{Raw: []string{"GET /?p={{p}} HTTP/1.1\nHost: {{Hostname}}\n\n"}},
		},
		{
			name: "keep-alive header",
			request: &httpprotocol.Request{
				Method: methodGet(), Path: []string{pipelinePath},
				Headers: map[string]string{"Connection": "keep-alive"},
			},
			want: "keep-alive",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, recorder := newConnectionRecorder(t)

			require.NoError(t, executePipelined(t, test.request, server.URL, payloads))

			recorder.mu.Lock()
			defer recorder.mu.Unlock()

			require.EqualValues(t, 1, recorder.connections.Load(), "the requests share one connection")
			require.Len(t, recorder.connection, payloads, "the server answers every request")

			for _, got := range recorder.connection {
				require.Equal(t, test.want, got, "Connection header of a request")
			}
		})
	}
}

// A template that asks to close the connection still gets it: the server sees
// the header and drops the connection, which cuts the block short.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestPipelineHonorsConnectionClose(t *testing.T) {
	server, recorder := newConnectionRecorder(t)
	request := &httpprotocol.Request{
		Method: methodGet(), Path: []string{pipelinePath},
		Headers: map[string]string{"Connection": "close"},
	}

	require.Error(t, executePipelined(t, request, server.URL, 10))

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	require.NotEmpty(t, recorder.connection)
	require.Equal(t, "close", recorder.connection[0])
}
