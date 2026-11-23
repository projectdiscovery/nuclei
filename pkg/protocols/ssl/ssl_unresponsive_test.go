package ssl //nolint:testpackage // it builds the unexported Request

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
)

var errConnectionRefused = errors.New("connection refused")

const dialedAddress = "{{Hostname}}"

// A request checks the address it dials against the host errors cache. The
// engine does not skip an ssl template for a down address, because it cannot
// tell which address the template dials (#8203).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnresponsiveDialedAddressIsSkipped(t *testing.T) {
	var dials atomic.Int32

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			dials.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	address := strings.TrimPrefix(server.URL, "https://")

	tests := []struct {
		name     string
		down     string
		wantDial bool
	}{
		{name: "another address down", down: "127.0.0.1:443", wantDial: true},
		{name: "dialed address down", down: address, wantDial: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dials.Store(0)

			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
			t.Cleanup(cache.Close)

			down := contextargs.NewWithInput(context.Background(), test.down)
			cache.MarkFailedOrRemove("http", down, errConnectionRefused)

			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "ssl-unresponsive"})
			executerOpts.HostErrorsCache = cache

			request := &Request{ID: "ssl-unresponsive", Address: dialedAddress}
			require.NoError(t, request.Compile(executerOpts))

			input := contextargs.NewWithInput(context.Background(), address)
			err := request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})

			if test.wantDial {
				require.NoError(t, err)
				require.Positive(t, dials.Load(), "did not dial an address that is not down")

				return
			}

			require.ErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			require.Zero(t, dials.Load(), "dialed an address marked down")
		})
	}
}
