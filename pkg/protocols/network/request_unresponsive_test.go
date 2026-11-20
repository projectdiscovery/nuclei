package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
)

var errConnectionRefused = errors.New("connection refused")

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
			require.NoError(t, request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, noop))

			select {
			case <-accepted:
				require.True(t, test.wantDial, "dialed an address marked down")
			case <-time.After(300 * time.Millisecond):
				require.False(t, test.wantDial, "did not dial an address that is not down")
			}
		})
	}
}
