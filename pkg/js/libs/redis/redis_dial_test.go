package redis

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// go-redis retries a failed dial 4 times, 100ms apart, on each of a command's 4 attempts: a closed
// port took at least 1.6s to fail.
func TestGetServerInfoFailsFastOnAClosedPort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows takes about a second to report a refused localhost dial")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NoError(t, listener.Close())

	start := time.Now()
	_, err = getServerInfo(context.Background(), "redis-closed-port", "127.0.0.1", addr.Port)
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}
