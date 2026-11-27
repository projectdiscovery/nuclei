package redis

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
// became "::1:6379" and failed with "too many colons in address" before reaching the server.
func TestRedisModuleDialsAnIPv6Host(t *testing.T) {
	testRedisModuleDials(t, "[::1]:0", "::1")
}

// The IPv4 literal must keep working unchanged.
func TestRedisModuleDialsAnIPv4Host(t *testing.T) {
	testRedisModuleDials(t, "127.0.0.1:0", "127.0.0.1")
}

func testRedisModuleDials(t *testing.T, listenAddr, host string) {
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

	executionID := "redis-dial-" + host
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	calls := map[string]func(ctx context.Context) error{
		"GetServerInfo": func(ctx context.Context) error {
			_, err := getServerInfo(ctx, executionID, host, port)
			return err
		},
		"GetServerInfoAuth": func(ctx context.Context) error {
			_, err := getServerInfoAuth(ctx, executionID, host, port, "x")
			return err
		},
		"Connect": func(ctx context.Context) error {
			_, err := connect(ctx, executionID, host, port, "x")
			return err
		},
		"IsAuthenticated": func(ctx context.Context) error {
			_, err := isAuthenticated(ctx, executionID, host, port)
			return err
		},
		"RunLuaScript": func(ctx context.Context) error {
			ctx = context.WithValue(ctx, "executionId", executionID) //nolint:staticcheck
			_, err := RunLuaScript(ctx, host, port, "x", "return 1", nil, nil)
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
			if err := <-done; err != nil {
				t.Logf("%s: %v", name, err)
			}
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
