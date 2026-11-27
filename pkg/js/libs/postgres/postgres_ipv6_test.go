package postgres

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
// became "::1:5432" and failed with "too many colons in address" before reaching the server.
func TestIsPostgresDialsAnIPv6Host(t *testing.T) {
	testPostgresModuleDials(t, "[::1]:0", "::1")
}

// The IPv4 literal must keep working unchanged.
func TestIsPostgresDialsAnIPv4Host(t *testing.T) {
	testPostgresModuleDials(t, "127.0.0.1:0", "127.0.0.1")
}

func testPostgresModuleDials(t *testing.T, listenAddr, host string) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Skipf("%s is unavailable: %v", listenAddr, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	executionID := "postgres-dial-" + host
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	_, err = isPostgres(context.Background(), executionID, host, port)
	if err != nil {
		require.NotContains(t, err.Error(), "too many colons")
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatalf("isPostgres never reached the IPv6 listener: %v", err)
	}
}
