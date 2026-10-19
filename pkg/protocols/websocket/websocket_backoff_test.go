package websocket

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostbackoff"
)

func newBackoffWebsocket(t *testing.T, address string, g *hostbackoff.Governor) *Request {
	t.Helper()
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "websocket-host-backoff"})
	executerOpts.HostBackoff = g

	request := &Request{ID: "websocket-host-backoff", Address: address}
	require.NoError(t, request.Compile(executerOpts))
	return request
}

func executeWebsocket(request *Request, address string) error {
	input := contextargs.NewWithInput(context.Background(), address)
	return request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {})
}

func TestWebsocketHandshakeFailureDoesNotBackOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	address := strings.Replace(server.URL, "http://", "ws://", 1)
	host := server.Listener.Addr().String()

	const step = 100 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.ObserveDial(host, nil)

	request := newBackoffWebsocket(t, address, g)
	require.Error(t, executeWebsocket(request, address))
	require.Zero(t, g.Delay(host), "a rejected upgrade means the port accepted the connection")
}

func TestWebsocketDialFailureBacksOffPreviouslyOpenPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host := listener.Addr().String()
	require.NoError(t, listener.Close())

	address := "ws://" + host
	const step = 100 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.ObserveDial(host, nil)

	request := newBackoffWebsocket(t, address, g)
	require.Error(t, executeWebsocket(request, address))
	require.Equal(t, step, g.Delay(host), "a refused TCP dial on a port that accepted before slows it")
}
