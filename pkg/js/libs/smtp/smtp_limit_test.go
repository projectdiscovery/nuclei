package smtp

import (
	"bytes"
	"context"
	"net"
	"net/textproto"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// A port that streams bytes without a newline used to be buffered whole: net/smtp reads replies
// through net/textproto, which reads a line until "\n" with no length limit.
func TestCallsBoundAReplyWithoutNewline(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client, *SMTPMessage)
	}{
		{"SendMail", func(c *Client, m *SMTPMessage) { _, _ = c.SendMail(m) }},
		{"IsOpenRelay", func(c *Client, m *SMTPMessage) { _, _ = c.IsOpenRelay(m) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := listenForLimitTest(t)
			go streamWithoutNewline(listener)
			client := newSMTPClientForLimitTest(t, listener.Addr().String())
			msg := (&SMTPMessage{}).From("scanner@example.com").To("admin@example.org")

			allocated := allocatedBy(func() {
				defer func() {
					_ = recover() // SendMail throws its error to the runtime
				}()
				tt.call(client, msg)
			})

			require.Less(t, allocated, uint64(64<<20), "allocated %d MiB reading one reply", allocated>>20)
		})
	}
}

// The cap must leave room for a normal dialogue.
func TestSendMailStillDeliversUnderTheReadLimit(t *testing.T) {
	listener := listenForLimitTest(t)
	received := serveOneSMTPSessionForLimitTest(listener)
	client := newSMTPClientForLimitTest(t, listener.Addr().String())

	msg := (&SMTPMessage{}).From("scanner@example.com").To("admin@example.org").Subject("hello").Body([]byte("world"))
	sent, err := client.SendMail(msg)
	require.NoError(t, err)
	require.True(t, sent)

	select {
	case data := <-received:
		require.Contains(t, data, "Subject: hello")
		require.Contains(t, data, "world")
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the message")
	}
}

func newSMTPClientForLimitTest(t *testing.T, addr string) *Client {
	t.Helper()

	executionID := "smtp-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() {
		protocolstate.Close(executionID)
	})

	vm := goja.New()
	vm.SetContextValue("executionId", executionID)
	vm.SetContextValue("ctx", context.Background())

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	obj, err := vm.New(vm.ToValue(NewSMTPClient), vm.ToValue(host), vm.ToValue(port))
	require.NoError(t, err)
	client, ok := obj.Export().(*Client)
	require.True(t, ok, "expected *Client export, got %T", obj.Export())

	return client
}

func listenForLimitTest(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	return listener
}

// streamWithoutNewline sends 256 MiB without a newline to each connection: bounded so the test
// cannot exhaust the machine when the limit is missing.
func streamWithoutNewline(listener net.Listener) {
	const streamBytes = 256 << 20
	chunk := bytes.Repeat([]byte("A"), 32<<10)
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
}

// allocatedBy reports how many bytes call allocated, freed or not.
func allocatedBy(call func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// serveOneSMTPSessionForLimitTest answers a single session like a minimal MTA with no
// extensions, and reports the DATA it was sent once the client quits.
func serveOneSMTPSessionForLimitTest(listener net.Listener) <-chan string {
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		tp := textproto.NewConn(conn)
		var data string
		_ = tp.PrintfLine("220 test ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch verb, _, _ := strings.Cut(line, " "); strings.ToUpper(verb) {
			case "EHLO", "HELO":
				_ = tp.PrintfLine("250 test")
			case "MAIL", "RCPT":
				_ = tp.PrintfLine("250 ok")
			case "DATA":
				_ = tp.PrintfLine("354 go ahead")
				body, err := tp.ReadDotBytes()
				if err != nil {
					return
				}
				data = string(body)
				_ = tp.PrintfLine("250 queued")
			case "QUIT":
				_ = tp.PrintfLine("221 bye")
				received <- data
				return
			default:
				_ = tp.PrintfLine("502 not implemented")
			}
		}
	}()
	return received
}
