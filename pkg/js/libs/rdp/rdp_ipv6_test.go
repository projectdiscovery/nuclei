package rdp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// The dial address was built with Sprintf("%s:%d"), so the bare IPv6 host nuclei passes as {{Host}}
// became "::1:3389" and failed with "too many colons in address" before reaching the server.
func TestRDPModuleDialsAnIPv6Host(t *testing.T) {
	testRDPModuleDials(t, "[::1]:0", "::1")
}

// The IPv4 literal must keep working unchanged.
func TestRDPModuleDialsAnIPv4Host(t *testing.T) {
	testRDPModuleDials(t, "127.0.0.1:0", "127.0.0.1")
}

func testRDPModuleDials(t *testing.T, listenAddr, host string) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Skipf("%s is unavailable: %v", listenAddr, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	executionID := "rdp-dial-" + host
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	calls := map[string]func(ctx context.Context) error{
		"IsRDP": func(ctx context.Context) error {
			_, err := isRDP(ctx, executionID, host, port)
			return err
		},
		"CheckRDPEncryption": func(ctx context.Context) error {
			_, err := checkRDPEncryption(ctx, executionID, host, port)
			return err
		},
		"CheckRDPAuth": func(ctx context.Context) error {
			_, err := checkRDPAuth(ctx, executionID, host, port)
			return err
		},
	}
	for name, call := range calls {
		for len(accepted) > 0 {
			<-accepted
		}
		// The module retries a dial that gets no answer, so stop each call once the listener has
		// seen it; reaching the listener is the result under test.
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- call(ctx) }()
		select {
		case <-accepted:
			cancel()
			<-done
		case err := <-done:
			cancel()
			if err != nil {
				require.NotContains(t, err.Error(), "too many colons", name)
			}
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Fatalf("%s never reached the listener: %v", name, err)
			}
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatalf("%s never reached the listener", name)
		}
	}
}
