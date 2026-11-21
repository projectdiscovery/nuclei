package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"bytes"
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

const pipelineDumpTimeout = 5 * time.Second

// wireServer answers 200 to each request it reads and keeps every byte it
// received, in arrival order. It frames a request by its Content-Length, so a
// body sent without one is left in the stream, as a real server would.
type wireServer struct {
	mu   sync.Mutex
	wire bytes.Buffer
}

func newWireServer(t *testing.T) (*wireServer, string) {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server := &wireServer{mu: sync.Mutex{}, wire: bytes.Buffer{}}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go server.serve(conn)
		}
	}()

	return server, "http://" + listener.Addr().String()
}

func (s *wireServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var pending []byte

	chunk := make([]byte, 4096)

	for {
		head, rest, found := bytes.Cut(pending, []byte("\r\n\r\n"))
		if found {
			size := contentLength(string(head))
			if len(rest) >= size {
				pending = rest[size:]

				_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				if err != nil {
					return
				}

				continue
			}
		}

		count, err := conn.Read(chunk)
		if count > 0 {
			s.mu.Lock()
			s.wire.Write(chunk[:count])
			s.mu.Unlock()

			pending = append(pending, chunk[:count]...)
		}

		if err != nil {
			return
		}
	}
}

func (s *wireServer) received() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.wire.String()
}

func contentLength(head string) int {
	for line := range strings.SplitSeq(head, "\r\n") {
		if key, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(key, "Content-Length") {
			size, _ := strconv.Atoi(strings.TrimSpace(value))

			return size
		}
	}

	return 0
}

// normalizeMessage sorts the header lines of a request, as the pipeline client
// writes them in the random order of a map.
func normalizeMessage(message string) string {
	head, body, _ := strings.Cut(message, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	slices.Sort(lines[1:])

	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

// messages splits a stream of requests with no body into its requests.
func messages(stream string) []string {
	var out []string

	for part := range strings.SplitSeq(stream, "\r\n\r\n") {
		if part != "" {
			out = append(out, normalizeMessage(part+"\r\n\r\n"))
		}
	}

	slices.Sort(out)

	return out
}

// pipelineDumpCase is a pipelined request and what its wire looks like.
type pipelineDumpCase struct {
	name    string
	request *httpprotocol.Request
	// bodies is true when the requests carry a body, which a stream cannot
	// be split on.
	bodies bool
}

//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func pipelineDumpCases() []pipelineDumpCase {
	return []pipelineDumpCase{
		{
			name: "get",
			request: &httpprotocol.Request{
				ID: "pipeline-dump-get", Method: methodGet(), Path: []string{"{{BaseURL}}/?p={{v}}"},
				Payloads: map[string]any{"v": []string{"1", "2", "3"}},
				Headers:  map[string]string{"Connection": "keep-alive", "X-Test": "a"},
				Pipeline: true, PipelineConcurrentConnections: 1,
			},
		},
		{
			name: "post",
			request: &httpprotocol.Request{
				ID: "pipeline-dump-post", Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPPost},
				Path: []string{"{{BaseURL}}/?p=1"}, Body: "p=1",
				Headers:  map[string]string{"Connection": "keep-alive"},
				Pipeline: true, PipelineConcurrentConnections: 1,
			},
			bodies: true,
		},
		{
			name: "host header",
			request: &httpprotocol.Request{
				ID: "pipeline-dump-host", Method: methodGet(), Path: []string{"{{BaseURL}}/x"},
				Headers:  map[string]string{"Host": "virtual.example"},
				Pipeline: true, PipelineConcurrentConnections: 1,
			},
		},
		{
			name: "encoded query",
			request: &httpprotocol.Request{
				ID: "pipeline-dump-query", Method: methodGet(), Path: []string{"{{BaseURL}}/a%2Fb/c?q=a%2Fb&z=%2F&y=1&x=<>"},
				Pipeline: true, PipelineConcurrentConnections: 1,
			},
		},
	}
}

// executeDumps runs request on target and returns the normalized request of
// each of its events, sorted.
func executeDumps(t *testing.T, request *httpprotocol.Request, target string) []string {
	t.Helper()

	var (
		lock  sync.Mutex
		dumps []string
	)

	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), target),
		make(output.InternalEvent), make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) {
			lock.Lock()
			defer lock.Unlock()

			dumped, _ := event.InternalEvent["request"].(string)
			dumps = append(dumps, normalizeMessage(dumped))
		})
	require.NoError(t, err)

	lock.Lock()
	defer lock.Unlock()

	slices.Sort(dumps)

	return dumps
}

// The request that -debug-req prints, stores and matches on must be the one
// the server reads (#8266). The pipeline client writes its own request, so a
// dump built the way http.Transport writes one adds lines the wire does not
// carry.
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelinedRequestDumpMatchesWire(t *testing.T) {
	for _, test := range pipelineDumpCases() {
		t.Run(test.name, func(t *testing.T) {
			compileWithCache(t, test.request, newDownHostErrorsCache(false))

			server, target := newWireServer(t)
			expected := executeDumps(t, test.request, target)
			require.NotEmpty(t, expected)

			actual := func() []string {
				if test.bodies {
					return []string{normalizeMessage(server.received())}
				}

				return messages(server.received())
			}

			// the body can arrive after the response to its request
			deadline := time.Now().Add(pipelineDumpTimeout)
			for time.Now().Before(deadline) && !slices.Equal(expected, actual()) {
				time.Sleep(10 * time.Millisecond)
			}

			require.Equal(t, expected, actual(), "the dump must equal the request on the wire")
		})
	}
}
