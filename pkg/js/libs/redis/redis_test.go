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

func TestLengthTooLarge(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{line: fmt.Sprintf("$%d\r\n", maxReadBytes), want: false},
		{line: fmt.Sprintf("$%d\r\n", maxReadBytes+1), want: true},
		{line: "$-1\r\n", want: false},
		{line: "+OK\r\n", want: false},
		{line: fmt.Sprintf("*%d\r\n", maxAggregate), want: false},
		{line: fmt.Sprintf("*%d\r\n", maxAggregate+1), want: true},
		{line: "$999999999999999999999\r\n", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			require.Equal(t, tt.want, lengthTooLarge([]byte(tt.line)))
		})
	}
}

// A short RESP length header used to make go-redis allocate the declared size before reading
// any of the payload, so the byte cap never applied.
func TestGetServerInfoAuthRejectsAHugeDeclaredLength(t *testing.T) {
	// The declared size is large enough to show up in the heap and small enough to survive a
	// missing check. The allowed growth stays under that allocation.
	tests := []struct {
		name   string
		header string
		limit  int64
	}{
		// The handshake reads a map. A bulk length has to be one of its values, or go-redis
		// rejects the header as the wrong type before allocating it.
		{name: "bulk string", header: fmt.Sprintf("%%1\r\n$1\r\nk\r\n$%d\r\n", 32<<20), limit: 16 << 20},
		{name: "array", header: fmt.Sprintf("*%d\r\n", 8<<20), limit: 64 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = listener.Close()
			})

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() {
					_ = conn.Close()
				}()
				_, _ = conn.Write([]byte(tt.header))
				_, _ = conn.Read(make([]byte, 1))
			}()

			executionID := "redis-" + strings.ReplaceAll(t.Name(), "/", "-")
			require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
			t.Cleanup(func() {
				protocolstate.Close(executionID)
			})

			addr, ok := listener.Addr().(*net.TCPAddr)
			require.True(t, ok)

			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err = getServerInfoAuth(ctx, executionID, "127.0.0.1", addr.Port, "")

			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			require.Error(t, err)
			// TotalAlloc counts the slice go-redis makes from the length header even when that
			// slice is freed before the call returns.
			growth := int64(after.TotalAlloc - before.TotalAlloc)
			require.Less(t, growth, tt.limit, "allocated %d MiB reading one reply", growth>>20)
		})
	}
}

// go-redis peeks for push notifications with a microseconds-long deadline. On Windows that
// peek always runs, and the timeout has to stay on that one read.
func TestLimitedConnDeadlineIsNotSticky(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
	})
	server := <-accepted
	t.Cleanup(func() {
		_ = server.Close()
	})

	lc := &limitedConn{Conn: client, remaining: maxReadBytes}
	require.NoError(t, lc.SetReadDeadline(time.Now().Add(-time.Second)))
	_, err = lc.Read(make([]byte, 8))
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())

	_, err = server.Write([]byte("+PONG\r\n"))
	require.NoError(t, err)
	require.NoError(t, lc.SetReadDeadline(time.Time{}))
	buf := make([]byte, 16)
	n, err := lc.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "+PONG\r\n", string(buf[:n]))
}
