package smtp

import (
	"context"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type receivedMail struct {
	from string
	to   []string
	data string
}

func TestSendMailDeliversTheMessage(t *testing.T) {
	listener := listenForTest(t)
	received := serveOneSMTPSession(listener)
	client := newSMTPClientForTest(t, context.Background(), listener.Addr().String())

	msg := (&SMTPMessage{}).From("scanner@example.com").To("admin@example.org").Subject("hello").Body([]byte("world"))
	sent, err := client.SendMail(msg)
	if err != nil || !sent {
		t.Fatalf("SendMail() = %v, %v; want true, nil", sent, err)
	}

	select {
	case mail := <-received:
		if !strings.Contains(mail.from, "<scanner@example.com>") {
			t.Errorf("MAIL command = %q, want the sender", mail.from)
		}
		if len(mail.to) != 1 || !strings.Contains(mail.to[0], "<admin@example.org>") {
			t.Errorf("RCPT commands = %q, want the one recipient", mail.to)
		}
		if !strings.Contains(mail.data, "Subject: hello") || !strings.Contains(mail.data, "world") {
			t.Errorf("DATA = %q, want the subject and body", mail.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the session end")
	}
}

// A server that accepts and never answers used to keep these calls, and the runtime
// abandoned around them, blocked for the life of the process.
func TestCallsReturnWhenTheContextIsDone(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client, *SMTPMessage)
	}{
		{"SendMail", func(c *Client, m *SMTPMessage) { _, _ = c.SendMail(m) }},
		{"IsOpenRelay", func(c *Client, m *SMTPMessage) { _, _ = c.IsOpenRelay(m) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := listenForTest(t)
			go holdConnections(listener)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := newSMTPClientForTest(t, ctx, listener.Addr().String())
			msg := (&SMTPMessage{}).From("scanner@example.com").To("admin@example.org")

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					_ = recover() // SendMail throws its error to the runtime
				}()
				tt.call(client, msg)
			}()

			select {
			case <-done:
				t.Fatal("returned before the server answered or the context was done")
			case <-time.After(200 * time.Millisecond):
			}

			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("still blocked after the context was done")
			}
		})
	}
}

func newSMTPClientForTest(t *testing.T, ctx context.Context, addr string) *Client {
	t.Helper()

	executionID := "smtp-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	if err := protocolstate.Init(&types.Options{ExecutionId: executionID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		protocolstate.Close(executionID)
	})

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", ctx)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := runtime.New(runtime.ToValue(NewSMTPClient), runtime.ToValue(host), runtime.ToValue(port))
	if err != nil {
		t.Fatal(err)
	}
	client, ok := obj.Export().(*Client)
	if !ok {
		t.Fatalf("expected *Client export, got %T", obj.Export())
	}
	return client
}

func listenForTest(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	return listener
}

// holdConnections accepts and never answers, like a tarpit.
func holdConnections(listener net.Listener) {
	var held []net.Conn
	for {
		conn, err := listener.Accept()
		if err != nil {
			for _, c := range held {
				_ = c.Close()
			}
			return
		}
		held = append(held, conn)
	}
}

// serveOneSMTPSession answers a single session like a minimal MTA with no extensions,
// and reports what it was sent once the client quits.
func serveOneSMTPSession(listener net.Listener) <-chan receivedMail {
	received := make(chan receivedMail, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		tp := textproto.NewConn(conn)
		var mail receivedMail
		_ = tp.PrintfLine("220 test ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch verb, _, _ := strings.Cut(line, " "); strings.ToUpper(verb) {
			case "EHLO", "HELO":
				_ = tp.PrintfLine("250 test")
			case "MAIL":
				mail.from = line
				_ = tp.PrintfLine("250 ok")
			case "RCPT":
				mail.to = append(mail.to, line)
				_ = tp.PrintfLine("250 ok")
			case "DATA":
				_ = tp.PrintfLine("354 go ahead")
				body, err := tp.ReadDotBytes()
				if err != nil {
					return
				}
				mail.data = string(body)
				_ = tp.PrintfLine("250 queued")
			case "QUIT":
				_ = tp.PrintfLine("221 bye")
				received <- mail
				return
			default:
				_ = tp.PrintfLine("502 not implemented")
			}
		}
	}()
	return received
}
