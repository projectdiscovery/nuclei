package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostbackoff"
)

const (
	hostTemplate     = "{{Host}}"
	hostPortTemplate = hostTemplate + ":{{Port}}"
)

// Each request in the total counts once, wherever an execution stops. These
// tests run a request that stops early or leaves requests unsent, and check the
// requests and errors the progress shows (#8259).

// A stop at the first match across addresses counts the addresses it leaves.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestStopAtFirstMatchAcrossAddressesCountsUnsent(t *testing.T) {
	first, _ := listen(t, nil, okReply)
	second, _ := listen(t, nil, okReply)
	request := &Request{
		Address:          []string{first, second},
		Inputs:           []*Input{{Data: pingData}},
		StopAtFirstMatch: true,
		Operators:        wordMatcher(okReply),
	}
	compileWithCache(t, request)
	progress := countRequests(request)

	matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), "127.0.0.1"))

	require.NoError(t, err)
	require.Equal(t, 1, matches)
	require.Equal(t, int64(2), progress.requests.Load())
	require.Zero(t, progress.errors.Load())
}

// An address that resolves to one the request has sent to is not sent again. It
// counts as processed.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestDuplicateAddressCountsAsProcessed(t *testing.T) {
	t.Run("two host entries", func(t *testing.T) {
		address, accepted := listen(t, nil, okReply)
		request := &Request{
			Address: []string{addressTemplate, hostPortTemplate},
			Inputs:  []*Input{{Data: pingData}},
		}
		compileWithCache(t, request)
		progress := countRequests(request)

		_, err := executeCounting(request, address)

		require.NoError(t, err)
		require.Equal(t, int64(2), progress.requests.Load())
		require.Zero(t, progress.errors.Load())
		require.Equal(t, int32(1), accepted.Load())
	})

	t.Run("two ports and a port in the input", func(t *testing.T) {
		address, _ := listen(t, nil, okReply)
		other, _ := listen(t, nil, okReply)
		request := &Request{
			Address: []string{addressTemplate},
			Port:    portsOf(t, address, other),
			Inputs:  []*Input{{Data: pingData}},
		}
		compileWithCache(t, request)
		progress := countRequests(request)

		_, err := executeCounting(request, address)

		require.NoError(t, err)
		require.Equal(t, int64(2), progress.requests.Load())
		require.Zero(t, progress.errors.Load())
	})
}

// An address the request cannot build fails once, and every request that it
// would have sent to it counts as processed.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestInputWithoutAddressCountsEveryRequest(t *testing.T) {
	tests := []struct {
		name    string
		address string
		input   string
	}{
		{name: "input that is not a url", address: addressTemplate, input: "http://%zz:1"},
		{name: "address without a port", address: hostTemplate, input: "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const payloads = 3

			request := &Request{
				Address:  []string{test.address},
				Inputs:   []*Input{{Data: pingData}},
				Payloads: map[string]any{payloadName: payloadValues(payloads)},
				Threads:  1,
			}
			compileWithCache(t, request)
			progress := countRequests(request)

			_, err := executeCounting(request, test.input)

			require.Error(t, err)
			require.Equal(t, int64(payloads), progress.requests.Load())
			require.Equal(t, int64(1), progress.errors.Load())
		})
	}
}

// A payload that fails to render counts as one processed request and one error,
// and the other payloads still run.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestPayloadThatFailsToRenderCounts(t *testing.T) {
	address, _ := listen(t, nil, okReply)
	request := &Request{
		Address:   []string{addressTemplate},
		Inputs:    []*Input{{Data: pingData}},
		Payloads:  map[string]any{payloadName: []string{"a", "{{to_number('x')}}", "c"}},
		Threads:   1,
		Operators: wordMatcher(okReply),
	}
	compileWithCache(t, request)
	progress := countRequests(request)

	matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), address))

	require.Error(t, err)
	require.Equal(t, 2, matches)
	require.Equal(t, int64(3), progress.requests.Load())
	require.Equal(t, int64(1), progress.errors.Load())
}

// A read that fails counts as one processed request and one error, as a failed
// write does.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestFailedReadCountsOneRequestAndOneError(t *testing.T) {
	address, _ := listen(t, nil, "")
	request := &Request{Address: []string{addressTemplate}, Inputs: []*Input{{Data: pingData, Read: readBytes}}}
	compileWithCache(t, request)
	progress := countRequests(request)

	_, err := executeCounting(request, address)

	require.Error(t, err)
	require.Equal(t, int64(1), progress.requests.Load())
	require.Equal(t, int64(1), progress.errors.Load())
}

// An input with an unresolved variable is not sent. It counts as processed, with
// no error, as an http request does.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresolvedVariableCountsAsProcessed(t *testing.T) {
	address, _ := listen(t, nil, okReply)
	request := &Request{Address: []string{addressTemplate}, Inputs: []*Input{{Data: "{{missing}}"}}}
	compileWithCache(t, request)
	progress := countRequests(request)

	events, err := executeCounting(request, address)

	require.NoError(t, err)
	require.Zero(t, events)
	require.Equal(t, int64(1), progress.requests.Load())
	require.Zero(t, progress.errors.Load())
}

// A cancel in the address loop counts the addresses it does not reach.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestCanceledAddressLoopCountsUnsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	first, _ := listen(t, func(string) { cancel() }, okReply)
	second, _ := listen(t, nil, okReply)
	request := &Request{Address: []string{first, second}, Inputs: []*Input{{Data: pingData}}}
	compileWithCache(t, request)
	progress := countRequests(request)

	_, err := executeMatching(request, contextargs.NewWithInput(ctx, "127.0.0.1"))

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int64(2), progress.requests.Load())
}

// A cancel in the payload loop counts the payloads it does not reach. Whether a
// payload that started after the cancel counts as an error depends on when its
// dial sees the cancel, so only the requests are checked.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestCanceledPayloadLoopCountsUnsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	address, _ := listen(t, func(string) { cancel() }, okReply)
	request := &Request{
		Address:  []string{addressTemplate},
		Inputs:   []*Input{{Data: pingData}},
		Payloads: map[string]any{payloadName: payloadValues(3)},
		Threads:  1,
	}
	compileWithCache(t, request)
	progress := countRequests(request)

	_, err := executeMatching(request, contextargs.NewWithInput(ctx, address))

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int64(3), progress.requests.Load())
}

// A request that a cancel stops while it waits for the host's backoff counts as
// one processed request and one error, as the rate-limit wait next to it does.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestCanceledBackoffWaitCountsRequest(t *testing.T) {
	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	address := listener.Addr().String()
	governor := hostbackoff.New(hostbackoff.Config{Step: 2 * time.Second})
	governor.Observe(address, 429, 0, nil)

	request, _ := newBackoffRequest(t, address, governor)
	progress := countRequests(request)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	_, err = executeMatching(request, contextargs.NewWithInput(ctx, address))

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, int64(1), progress.requests.Load())
	require.Equal(t, int64(1), progress.errors.Load())
}
