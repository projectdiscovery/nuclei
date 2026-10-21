package redis

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// A port that streams bytes without a newline used to be buffered whole: go-redis reads a reply
// line until "\n" with no length limit.
func TestGetServerInfoAuthBoundsAReplyWithoutNewline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	// Bounded so the test cannot exhaust the machine when the limit is missing.
	const streamBytes = 256 << 20
	chunk := bytes.Repeat([]byte("A"), 32<<10)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() {
					_ = conn.Close()
				}()
				for sent := 0; sent < streamBytes; sent += len(chunk) {
					if _, err := conn.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()

	executionID := "redis-" + strings.ReplaceAll(t.Name(), "/", "-")
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() {
		protocolstate.Close(executionID)
	})

	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(10 * time.Millisecond):
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak.Load() {
				peak.Store(m.HeapInuse)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = getServerInfoAuth(ctx, executionID, "127.0.0.1", addr.Port, "")
	close(done)

	require.Error(t, err)
	growth := int64(peak.Load()) - int64(before.HeapInuse)
	require.Less(t, growth, int64(64<<20), "heap grew %d MiB reading one reply", growth>>20)
}

func TestGetServerInfoAuthReadsAnInfoReply(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	const info = "# Server\r\nredis_version:7.2.4\r\n"
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveRESP(conn, info)
		}
	}()

	executionID := "redis-" + strings.ReplaceAll(t.Name(), "/", "-")
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() {
		protocolstate.Close(executionID)
	})

	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := getServerInfoAuth(ctx, executionID, "127.0.0.1", addr.Port, "")
	require.NoError(t, err)
	require.Equal(t, info, got)
}

// serveRESP answers HELLO as a Redis without RESP3 does, so the client falls back to RESP2, and
// CLIENT, PING and INFO as a Redis would.
func serveRESP(conn net.Conn, info string) {
	defer func() {
		_ = conn.Close()
	}()

	rd := bufio.NewReader(conn)
	for {
		command, err := readRESPCommand(rd)
		if err != nil {
			return
		}

		var reply string
		switch strings.ToUpper(command) {
		case "HELLO":
			reply = "-ERR unknown command 'HELLO'\r\n"
		case "PING":
			reply = "+PONG\r\n"
		case "INFO":
			reply = fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)
		default:
			reply = "+OK\r\n"
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// readRESPCommand reads one request array and returns its command name.
func readRESPCommand(rd *bufio.Reader) (string, error) {
	header, err := rd.ReadString('\n')
	if err != nil {
		return "", err
	}
	count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "*")))
	if err != nil {
		return "", err
	}

	var command string
	for i := range count {
		if _, err := rd.ReadString('\n'); err != nil { // $<len>
			return "", err
		}
		arg, err := rd.ReadString('\n')
		if err != nil {
			return "", err
		}
		if i == 0 {
			command = strings.TrimSpace(arg)
		}
	}

	return command, nil
}
