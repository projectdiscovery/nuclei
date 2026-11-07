package redis

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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
	tests := []struct {
		name string
		info string
	}{
		{name: "info", info: "# Server\r\nredis_version:7.2.4\r\n"},
		// A bulk payload's lines are data, even when they start like a RESP length header.
		{name: "header-like lines", info: "# Server\r\n*abc\r\n$ 5 dollars\r\n%x\r\n$99999999999\r\n"},
		// Each line used to cost a copy of what was left of the read buffer.
		{name: "many short lines", info: strings.Repeat("\n", 1<<20)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = listener.Close()
			})

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go serveRESP(conn, tt.info)
				}
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
			got, err := getServerInfoAuth(ctx, executionID, "127.0.0.1", addr.Port, "")

			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			require.NoError(t, err)
			require.Equal(t, tt.info, got)
			growth := int64(after.TotalAlloc - before.TotalAlloc)
			require.Less(t, growth, int64(64<<20), "allocated %d MiB reading one reply", growth>>20)
		})
	}
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

func TestDeclaredPayload(t *testing.T) {
	tests := []struct {
		line     string
		overlong bool
		payload  int64
		tooLarge bool
	}{
		{line: fmt.Sprintf("$%d\r", maxReadBytes), payload: maxReadBytes + 2},
		{line: fmt.Sprintf("$%d\r", maxReadBytes+1), tooLarge: true},
		{line: "=10\r", payload: 12},
		{line: "$-1\r"},
		{line: "+OK\r"},
		{line: "+OK\r", overlong: true},
		{line: fmt.Sprintf("*%d\r", maxAggregate)},
		{line: fmt.Sprintf("*%d\r", maxAggregate+1), tooLarge: true},
		{line: "$999999999999999999999\r", tooLarge: true},
		{line: "*abc\r", tooLarge: true},
		{line: "$000000000000000000000000000000", overlong: true, tooLarge: true},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			payload, err := declaredPayload([]byte(tt.line), tt.overlong)
			if tt.tooLarge {
				require.ErrorIs(t, err, errReadLimit)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.payload, payload)
		})
	}
}

// The check that rejects a length header has to land on the "\n" when the header arrives over
// several reads, and payload bytes have to pass whatever they contain.
func TestLimitedConnFollowsFramingAcrossReads(t *testing.T) {
	const ok = "*2\r\n$5\r\n*abc\n\r\n$-1\r\n+OK\r\n"
	tooLarge := fmt.Sprintf("$%d\r\n", maxReadBytes+1)

	tests := []struct {
		name    string
		stream  string
		want    string
		wantErr error
	}{
		{name: "payload passes", stream: ok, want: ok},
		{name: "header rejected", stream: ok + tooLarge + "x", want: ok + tooLarge[:len(tooLarge)-1], wantErr: errReadLimit},
	}
	for _, tt := range tests {
		for _, size := range []int{1, 3, 64} {
			t.Run(fmt.Sprintf("%s/%d", tt.name, size), func(t *testing.T) {
				lc := &limitedConn{Conn: &chunkedConn{data: []byte(tt.stream), size: size}, remaining: maxReadBytes}
				got, err := io.ReadAll(lc)
				require.Equal(t, tt.want, string(got))
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	}
}

// chunkedConn returns data at most size bytes per read, then io.EOF.
type chunkedConn struct {
	net.Conn
	data []byte
	size int
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b[:min(len(b), c.size)], c.data)
	c.data = c.data[n:]
	return n, nil
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
