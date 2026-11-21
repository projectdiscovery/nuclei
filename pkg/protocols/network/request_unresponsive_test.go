package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
)

var errConnectionRefused = errors.New("connection refused")

const (
	pingData        = "ping"
	addressTemplate = "{{Hostname}}"
)

// A request checks the address it dials against the host errors cache, not the
// input it is given. The input of a template run for https://127.0.0.1 is
// 127.0.0.1:443, and a refused https port says nothing about the request's own
// address (#8203).
//
//nolint:paralleltest // the test options are global
func TestUnresponsiveInputDoesNotSkipDialedAddress(t *testing.T) {
	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan struct{}, 4)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			accepted <- struct{}{}

			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()

	address := listener.Addr().String()

	tests := []struct {
		name     string
		down     string
		wantDial bool
	}{
		{name: "input address down", down: "127.0.0.1:443", wantDial: true},
		{name: "dialed address down", down: address, wantDial: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, opts := newBackoffRequest(t, address, nil)
			cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
			t.Cleanup(cache.Close)

			down := contextargs.NewWithInput(context.Background(), test.down)
			cache.MarkFailedOrRemove("http", down, errConnectionRefused)
			opts.HostErrorsCache = cache

			input := contextargs.NewWithInput(context.Background(), "127.0.0.1:443")
			noop := func(*output.InternalWrappedEvent) {}

			err := request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, noop)
			if test.wantDial {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			}

			select {
			case <-accepted:
				require.True(t, test.wantDial, "dialed an address marked down")
			case <-time.After(300 * time.Millisecond):
				require.False(t, test.wantDial, "did not dial an address that is not down")
			}
		})
	}
}

// listen serves loopback connections. For each one it waits for the request,
// runs onRequest with the server's address, then writes reply and closes. It
// returns the address and the number of connections the server accepted.
func listen(t *testing.T, onRequest func(address string), reply string) (string, *atomic.Int32) {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	address := listener.Addr().String()
	accepted := &atomic.Int32{}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			accepted.Add(1)

			_, _ = conn.Read(make([]byte, 16))

			if onRequest != nil {
				onRequest(address)
			}

			_, _ = conn.Write([]byte(reply))
			_ = conn.Close()
		}
	}()

	return address, accepted
}

// closedAddress returns a loopback address that refuses connections.
func closedAddress(t *testing.T) string {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	return listener.Addr().String()
}

// compileWithCache compiles request with a host errors cache that holds no
// address yet, and returns the cache.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func compileWithCache(t *testing.T, request *Request) *hosterrorscache.Cache {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-unresponsive"})
	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)

	executerOpts.HostErrorsCache = cache
	request.ID = "network-unresponsive"
	request.ReadSize = 2
	require.NoError(t, request.Compile(executerOpts))

	return cache
}

func markDown(cache *hosterrorscache.Cache, address string) {
	cache.MarkFailedOrRemove("http", contextargs.NewWithInput(context.Background(), address), errConnectionRefused)
}

// executeCounting runs request against input and returns the number of events
// it passed to the callback and its error.
func executeCounting(request *Request, input string) (int, error) {
	var events int

	target := contextargs.NewWithInput(context.Background(), input)
	err := request.ExecuteWithResults(target, output.InternalEvent{}, output.InternalEvent{},
		func(*output.InternalWrappedEvent) { events++ })

	return events, err
}

// A request skipped for an unresponsive address reports the skip, as an http
// request does. It sent nothing, so it emits no event that an executer would
// read as a response (#8230).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresponsiveAddressReportsSkip(t *testing.T) {
	address, accepted := listen(t, nil, "ok")
	request := &Request{Address: []string{address}, Inputs: []*Input{{Data: pingData}}}
	markDown(compileWithCache(t, request), address)

	events, err := executeCounting(request, address)

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Zero(t, events)
	require.Zero(t, accepted.Load(), "dialed an address marked down")
}

// An address that goes down while payload requests run ends the execution with
// the skip. A request that failed before then keeps its own error, which takes
// precedence.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresponsiveAddressWithPayloads(t *testing.T) {
	tests := []struct {
		name  string
		input *Input
		reply string
		// failed is whether the first request fails to read its response.
		failed bool
	}{
		{name: "after a response", input: &Input{Data: pingData}, reply: "ok"},
		{name: "after a failed request", input: &Input{Data: pingData, Read: 2}, failed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var cache *hosterrorscache.Cache

			// The server marks the address down once the first request is in,
			// so the dial itself does not reset the mark.
			address, accepted := listen(t, func(address string) { markDown(cache, address) }, test.reply)
			request := &Request{
				Address:  []string{address},
				Inputs:   []*Input{test.input},
				Payloads: map[string]any{"value": []string{"a", "b", "c"}},
				Threads:  1,
			}
			cache = compileWithCache(t, request)

			_, err := executeCounting(request, address)

			require.Equal(t, int32(1), accepted.Load(), "dialed an address marked down")

			if test.failed {
				require.Error(t, err)
				require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)

				return
			}

			require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
		})
	}
}

// A skipped address does not stop the request from the others, and the
// execution still reports the skip when no request failed.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresponsiveAddressAmongOthers(t *testing.T) {
	other, otherAccepted := listen(t, nil, "ok")
	down, downAccepted := listen(t, nil, "ok")
	request := &Request{Address: []string{other, down}, Inputs: []*Input{{Data: pingData}}}
	markDown(compileWithCache(t, request), down)

	events, err := executeCounting(request, "127.0.0.1")

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Equal(t, 1, events)
	require.Equal(t, int32(1), otherAccepted.Load())
	require.Zero(t, downAccepted.Load(), "dialed an address marked down")
}

// A request error takes precedence over the skip of another address, as it
// does for an http request, wherever the addresses that respond are.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestRequestErrorTakesPrecedenceOverSkip(t *testing.T) {
	tests := []struct {
		name  string
		order func(refused, ok, down string) []string
	}{
		{
			name:  "refused then down",
			order: func(refused, _, down string) []string { return []string{refused, down} },
		},
		{
			name:  "refused, responds, then down",
			order: func(refused, ok, down string) []string { return []string{refused, ok, down} },
		},
		{
			name:  "down, refused, then responds",
			order: func(refused, ok, down string) []string { return []string{down, refused, ok} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			down, downAccepted := listen(t, nil, "ok")
			ok, _ := listen(t, nil, "ok")
			request := &Request{Address: test.order(closedAddress(t), ok, down), Inputs: []*Input{{Data: pingData}}}
			markDown(compileWithCache(t, request), down)

			_, err := executeCounting(request, "127.0.0.1")

			require.Error(t, err)
			require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			require.Zero(t, downAccepted.Load(), "dialed an address marked down")
		})
	}
}

// An address that is down for one of the template's ports does not stop the
// request to the others.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresponsivePortAmongOthers(t *testing.T) {
	down, _ := listen(t, nil, "ok")
	other, _ := listen(t, nil, "ok")
	_, downPort, err := net.SplitHostPort(down)
	require.NoError(t, err)
	_, otherPort, err := net.SplitHostPort(other)
	require.NoError(t, err)

	request := &Request{
		Address: []string{addressTemplate},
		Port:    downPort + "," + otherPort,
		Inputs:  []*Input{{Data: pingData}},
	}
	markDown(compileWithCache(t, request), down)

	events, err := executeCounting(request, "127.0.0.1")

	require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
	require.Equal(t, 1, events)
}
