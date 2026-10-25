package network

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostbackoff"
)

func newBackoffRequest(t *testing.T, address string, g *hostbackoff.Governor) (*Request, *protocols.ExecutorOptions) {
	t.Helper()
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-host-backoff"})
	executerOpts.HostBackoff = g

	request := &Request{ID: "network-host-backoff", Address: []string{address}, ReadSize: 2}
	require.NoError(t, request.Compile(executerOpts))
	return request, executerOpts
}

func execute(request *Request, address string) error {
	input := contextargs.NewWithInput(context.Background(), address)
	return request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {})
}

func TestFailedDialBacksOffHost(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()

	g := hostbackoff.New(hostbackoff.Config{Step: 100 * time.Millisecond})
	request, _ := newBackoffRequest(t, address, g)

	require.NoError(t, execute(request, address))
	require.NoError(t, listener.Close())
	require.Error(t, execute(request, address))
	require.Equal(t, 100*time.Millisecond, g.Delay(address), "a port that accepted and now refuses is pushing back")
}

func TestClosedPortIsNotBackedOff(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	g := hostbackoff.New(hostbackoff.Config{Step: 100 * time.Millisecond})
	request, _ := newBackoffRequest(t, address, g)

	require.Error(t, execute(request, address))
	require.Error(t, execute(request, address))
	require.Zero(t, g.Delay(address), "a port that never accepted is closed, not blocking")
}

func TestSuccessfulDialWaitsThenDecays(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()
	address := listener.Addr().String()

	const step = 150 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.Observe(address, http.StatusTooManyRequests, 0, nil)
	request, _ := newBackoffRequest(t, address, g)

	start := time.Now()
	require.NoError(t, execute(request, address))
	require.GreaterOrEqual(t, time.Since(start), step, "a host that earned a delay is paced")
	require.Zero(t, g.Delay(address), "a connection that succeeds is recovery")
}

func TestMultiPortProbeWaitsThenDecays(t *testing.T) {
	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = openLn.Close() })
	go func() {
		for {
			conn, err := openLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	openAddr := openLn.Addr().String()
	_, openPort, err := net.SplitHostPort(openAddr)
	require.NoError(t, err)

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := closedLn.Addr().String()
	_, closedPort, err := net.SplitHostPort(closedAddr)
	require.NoError(t, err)
	require.NoError(t, closedLn.Close())

	const step = 150 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.Observe(openAddr, http.StatusTooManyRequests, 0, nil)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-host-backoff"})
	executerOpts.HostBackoff = g

	request := &Request{
		ID:       "network-host-backoff",
		Address:  []string{"{{Hostname}}"},
		Port:     openPort + "," + closedPort,
		ReadSize: 2,
	}
	require.NoError(t, request.Compile(executerOpts))

	start := time.Now()
	require.NoError(t, execute(request, "127.0.0.1"))
	require.GreaterOrEqual(t, time.Since(start), step, "a multi-port probe waits on a host:port that already has a delay")
	require.Zero(t, g.Delay(openAddr), "a probe that connects is recovery")
	require.Zero(t, g.Delay(closedAddr), "a port that never accepted stays unpaced")
}

func TestMultiPortProbeFailureBacksOffPreviouslyOpenPort(t *testing.T) {
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := closedLn.Addr().String()
	_, closedPort, err := net.SplitHostPort(closedAddr)
	require.NoError(t, err)
	require.NoError(t, closedLn.Close())

	otherLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	otherAddr := otherLn.Addr().String()
	_, otherPort, err := net.SplitHostPort(otherAddr)
	require.NoError(t, err)
	require.NoError(t, otherLn.Close())

	const step = 100 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.ObserveDial(closedAddr, nil)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-host-backoff"})
	executerOpts.HostBackoff = g

	request := &Request{
		ID:      "network-host-backoff",
		Address: []string{"{{Hostname}}"},
		Port:    closedPort + "," + otherPort,
	}
	require.NoError(t, request.Compile(executerOpts))

	require.Error(t, execute(request, "127.0.0.1"))
	require.Equal(t, step, g.Delay(closedAddr), "a probe that fails on a port that accepted before slows it")
	require.Zero(t, g.Delay(otherAddr), "a port that never accepted stays unpaced")
}

func TestTLSHandshakeFailureDoesNotBackOff(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("not tls"))
			_ = conn.Close()
		}
	}()
	address := listener.Addr().String()

	const step = 100 * time.Millisecond
	g := hostbackoff.New(hostbackoff.Config{Step: step})
	g.ObserveDial(address, nil)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-host-backoff"})
	executerOpts.HostBackoff = g

	request := &Request{ID: "network-host-backoff", Address: []string{"tls://" + address}, ReadSize: 2}
	require.NoError(t, request.Compile(executerOpts))

	err = execute(request, address)
	require.Error(t, err)
	require.Zero(t, g.Delay(address), "a TLS handshake failure after TCP connected stays with the template: %v", err)
}
