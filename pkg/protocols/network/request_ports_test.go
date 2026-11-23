package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
)

const (
	okReply = "ok"
	// readBytes makes an input read the 2-byte reply, and fail when there is none.
	readBytes = 2
	// wsaeconnreset is WSAECONNRESET, which the syscall package defines on Windows only.
	wsaeconnreset = 10054
)

// resetErrno returns the errno of a connection that its peer reset. Windows
// words it as "forcibly closed by the remote host", not as "reset by peer", and
// its syscall.ECONNRESET is a placeholder that no network call returns.
func resetErrno() syscall.Errno {
	if runtime.GOOS == "windows" {
		return syscall.Errno(wsaeconnreset)
	}

	return syscall.ECONNRESET
}

// portsOf returns the ports of host:port addresses, joined as a template's port list.
func portsOf(t *testing.T, addresses ...string) string {
	t.Helper()

	ports := make([]string, len(addresses))

	for index, address := range addresses {
		_, port, err := net.SplitHostPort(address)
		require.NoError(t, err)

		ports[index] = port
	}

	return strings.Join(ports, ",")
}

// executeMatching runs request against target and returns the number of events
// that matched and its error. A failed address also reports an event, with no
// match, so executeCounting would count it.
func executeMatching(request *Request, target *contextargs.Context) (int, error) {
	var matches int

	err := request.ExecuteWithResults(target, output.InternalEvent{},
		output.InternalEvent{}, func(event *output.InternalWrappedEvent) {
			if event.HasOperatorResult() {
				matches++
			}
		})

	return matches, err
}

// A port whose request fails does not stop the request to the ports after it.
// Each port is its own service, and its failure is reported when the others are
// done.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestFailedPortDoesNotStopOtherPorts(t *testing.T) {
	t.Run("read fails", func(t *testing.T) {
		failing, _ := listen(t, nil, "")
		answering, _ := listen(t, nil, okReply)
		request := &Request{
			Address:   []string{addressTemplate},
			Port:      portsOf(t, failing, answering),
			Inputs:    []*Input{{Data: pingData, Read: readBytes}},
			Operators: wordMatcher(okReply),
		}
		compileWithCache(t, request)

		matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), "127.0.0.1"))

		require.Equal(t, 1, matches)
		require.Error(t, err)
		require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	})

	t.Run("tls handshake fails", func(t *testing.T) {
		plain, _ := listen(t, nil, "")
		secure := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		secure.Config.ErrorLog = log.New(io.Discard, "", 0) // the port check connects without a handshake

		secure.StartTLS()
		t.Cleanup(secure.Close)

		request := &Request{
			Address:   []string{"tls://" + addressTemplate},
			Port:      portsOf(t, plain, secure.Listener.Addr().String()),
			Inputs:    []*Input{{Data: "GET / HTTP/1.0\r\n\r\n"}},
			Operators: wordMatcher("HT"),
		}
		compileWithCache(t, request)

		matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), "127.0.0.1"))

		require.Equal(t, 1, matches)
		require.Error(t, err)
		require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	})
}

// listenReset serves loopback connections. It resets the connection that
// carries a request, and closes the port check's normally. It returns the
// address.
func listenReset(t *testing.T) string {
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

			if size, _ := conn.Read(make([]byte, 16)); size > 0 {
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0)
				}
			}

			_ = conn.Close()
		}
	}()

	return listener.Addr().String()
}

// The failures of several ports are all returned, and the cause of the first is
// the cause of the error, which -ms reports. Their causes differ, as errkit
// keeps one of several equal errors.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestFailedPortsJoinErrors(t *testing.T) {
	closing, _ := listen(t, nil, "")
	request := &Request{
		Address: []string{addressTemplate},
		Port:    portsOf(t, closing, listenReset(t)),
		Inputs:  []*Input{{Data: pingData, Read: readBytes}},
	}
	compileWithCache(t, request)

	_, err := executeCounting(request, "127.0.0.1")

	require.Error(t, err)
	require.Contains(t, err.Error(), `cause="EOF"`, "the cause of the first failure is the cause of the error")
	require.ErrorIs(t, err, resetErrno(), "the failure of the reset port is returned too")
}

// A canceled scan stops the port loop. The ports it does not reach count as
// processed, and the cancel is returned once, not as a failure of each port.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestCanceledScanStopsPortLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The server sees the port check's connection first, so its 2nd call is the
	// request.
	var calls atomic.Int32

	first, _ := listen(t, func(string) {
		if calls.Add(1) == 2 {
			cancel()
		}
	}, okReply)
	second, _ := listen(t, nil, okReply)
	third, _ := listen(t, nil, okReply)
	request := &Request{
		Address:   []string{addressTemplate},
		Port:      portsOf(t, first, second, third),
		Inputs:    []*Input{{Data: pingData}},
		Operators: wordMatcher(okReply),
	}
	compileWithCache(t, request)
	progress := countRequests(request)

	matches, err := executeMatching(request, contextargs.NewWithInput(ctx, "127.0.0.1"))

	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, multierr.Errors(err), 1)
	require.Equal(t, 1, matches)
	require.Equal(t, int64(3), progress.requests.Load())
}

// A port whose request fails takes precedence over a skipped port, wherever the
// skipped port is. The skipped port is still not dialed past the port check.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestFailedPortTakesPrecedenceOverSkippedPort(t *testing.T) {
	tests := []struct {
		name  string
		order func(failing, down string) []string
	}{
		{name: "failed then skipped", order: func(failing, down string) []string { return []string{failing, down} }},
		{name: "skipped then failed", order: func(failing, down string) []string { return []string{down, failing} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failing, _ := listen(t, nil, "")
			down, downAccepted := listen(t, nil, okReply)
			request := &Request{
				Address: []string{addressTemplate},
				Port:    portsOf(t, test.order(failing, down)...),
				Inputs:  []*Input{{Data: pingData, Read: readBytes}},
			}
			markDown(compileWithCache(t, request), down)

			_, err := executeCounting(request, "127.0.0.1")

			require.Error(t, err)
			require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			// The listener counts a connection in its own goroutine, so the count
			// can trail the scan: wait for the port check's dial, then make sure
			// no other one follows.
			require.Eventually(t, func() bool { return downAccepted.Load() == 1 }, 5*time.Second, 5*time.Millisecond,
				"the port check did not dial the port marked down")
			require.Never(t, func() bool { return downAccepted.Load() > 1 }, 200*time.Millisecond, 10*time.Millisecond,
				"only the port check dials the port marked down")
		})
	}
}
