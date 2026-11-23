package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const (
	pongReply = "pong\r\n"
	// finalReadTimeout is short so that the test with a silent server stays fast.
	finalReadTimeout = 200 * time.Millisecond
)

// traceEntry is one call to the output writer's Request.
type traceEntry struct {
	input string
	err   error
}

// recordTrace makes request record its trace entries, and returns a function
// that reads them.
func recordTrace(request *Request) func() []traceEntry {
	var (
		mutex   sync.Mutex
		entries []traceEntry
	)

	writer, ok := request.options.Output.(*testutils.MockOutputWriter)
	if !ok {
		panic("the test executer options do not use the mock output writer")
	}

	writer.RequestCallback = func(_, input, _ string, err error) {
		mutex.Lock()
		defer mutex.Unlock()

		entries = append(entries, traceEntry{input: input, err: err})
	}

	return func() []traceEntry {
		mutex.Lock()
		defer mutex.Unlock()

		return append([]traceEntry(nil), entries...)
	}
}

// listenAnswering returns the address of a server that answers each request
// with reply, and then closes the connection or, when keepOpen is true, holds
// it open until the client closes it.
func listenAnswering(t *testing.T, reply string, keepOpen bool) string {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				_, _ = conn.Read(make([]byte, 16))

				if reply != "" {
					_, _ = conn.Write([]byte(reply))
				}

				if keepOpen {
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
		}
	}()

	return listener.Addr().String()
}

// The final read is optional: a request that matched without it is not an
// error. Its end with EOF or a timeout must not write an error to the trace, so
// that -elog stays empty and -tlog has one entry for the request (#8264).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestFinalReadEndWritesOneTraceEntryWithoutError(t *testing.T) {
	tests := []struct {
		name     string
		reply    string
		keepOpen bool
		// read is the input's read size, 0 for no read.
		read    int
		matches int
	}{
		{name: "read then server closes", reply: pongReply, read: len(pongReply), matches: 1},
		{name: "read then server stays open", reply: pongReply, keepOpen: true, read: len(pongReply), matches: 1},
		{name: "no read, server closes", reply: pongReply, matches: 1},
		{name: "no read, server closes without a reply"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address := listenAnswering(t, test.reply, test.keepOpen)
			request := &Request{
				Address:   []string{addressTemplate},
				Inputs:    []*Input{{Data: pingData, Read: test.read}},
				Operators: wordMatcher("pong"),
			}
			compileWithCache(t, request)
			request.ReadSize = 0
			request.options.Options.SetTimeouts(&types.Timeouts{TcpReadTimeout: finalReadTimeout})
			progress := countRequests(request)
			entries := recordTrace(request)

			matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), address))

			require.NoError(t, err)
			require.Equal(t, test.matches, matches)
			require.Equal(t, int64(1), progress.requests.Load())
			require.Zero(t, progress.errors.Load())

			trace := entries()
			require.Len(t, trace, 1)
			require.NoError(t, trace[0].err)
			require.Equal(t, address, trace[0].input)
		})
	}
}
