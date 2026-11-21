package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// holdingServer reads pipelined requests and answers each one only after
// release closes. It returns the address, a channel that receives once per
// request it has read, and release.
func holdingServer(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	// It runs before the listener closes, so the handler never blocks forever.
	t.Cleanup(releaseOnce)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)

		for {
			_, err := http.ReadRequest(reader)
			if err != nil {
				return
			}

			arrived <- struct{}{}

			<-release

			_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			if err != nil {
				return
			}
		}
	}()

	return listener.Addr().String(), arrived, releaseOnce
}

// A pipelined block whose input context is canceled while it sends waits for
// the requests it already sent, so no result reaches the callback after the
// block returns, as with threads (#8255).
//
//nolint:paralleltest // testutils.Init state is shared
func TestPipelineCancelWaitsForSentRequests(t *testing.T) {
	address, arrived, release := holdingServer(t)

	request := pipelined("pipe-cancel", map[string]any{"v": numberedPayloads(3)}, skipPathPayload)
	request.Operators = matchStatusOK()
	progress := compileWithCache(t, request, newDownHostErrorsCache(false))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// The loop counts a request when it takes it, so the second count comes
	// after the first request started. Once the server holds that request,
	// cancel, and answer it 200ms later.
	progress.onRequest = func(count int64) {
		if count != 2 {
			return
		}

		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Error("the server did not get the first request")
		}

		cancel()
		time.AfterFunc(200*time.Millisecond, release)
	}

	var events atomic.Int32

	err := request.ExecuteWithResults(contextargs.NewWithInput(ctx, "http://"+address),
		make(output.InternalEvent), make(output.InternalEvent),
		func(*output.InternalWrappedEvent) { events.Add(1) })

	require.ErrorIs(t, err, context.Canceled)
	// The loop took the second request but did not send it.
	require.EqualValues(t, 1, events.Load(), "results reported before the block returns")
}
