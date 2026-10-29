package redis

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
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

// go-redis's default logger wrote each failed dial straight to stderr, past nuclei's logger and
// its level.
func TestGoRedisLogsAreGologgerWarnings(t *testing.T) {
	logs := &recordingWriter{}
	gologger.DefaultLogger.SetWriter(logs)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	t.Cleanup(func() {
		// gologger's own defaults: it has no getter to save the previous ones.
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NoError(t, listener.Close())

	_, err = getServerInfo(context.Background(), "redis-log-level", "127.0.0.1", addr.Port)
	require.Error(t, err)

	warnings := logs.at(levels.LevelWarning)
	require.NotEmpty(t, warnings)
	require.Contains(t, warnings[0], "failed to dial")
}

type recordingWriter struct {
	mu    sync.Mutex
	lines map[levels.Level][]string
}

func (w *recordingWriter) Write(data []byte, level levels.Level) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lines == nil {
		w.lines = make(map[levels.Level][]string)
	}
	w.lines[level] = append(w.lines[level], strings.TrimSpace(string(data)))
}

func (w *recordingWriter) at(level levels.Level) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lines[level]
}
