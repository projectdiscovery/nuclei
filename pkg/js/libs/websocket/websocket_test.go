package websocket

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/projectdiscovery/goja"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// echoHandler upgrades the connection, greets, then echoes every message
// back with its original opcode until the client closes.
func echoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		upgrader := ws.HTTPUpgrader{
			Protocol: func(protocol string) bool { return protocol == "chat" },
			Header:   http.Header{"X-Server": []string{"echo"}},
		}
		conn, _, _, err := upgrader.Upgrade(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		if err := wsutil.WriteServerText(conn, []byte("welcome")); err != nil {
			return
		}
		for {
			payload, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if string(payload) == "close-me" {
				_ = ws.WriteFrame(conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusGoingAway, "bye")))
				return
			}
			if err := wsutil.WriteServerMessage(conn, op, payload); err != nil {
				return
			}
		}
	}
}

func initExec(t *testing.T, options *types.Options) string {
	t.Helper()
	executionID := "websocket-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	options.ExecutionId = executionID
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	return executionID
}

// newRuntimeClient constructs a *Client through the goja runtime exactly as a
// nuclei template would.
func newRuntimeClient(t *testing.T, executionID, rawURL string, opts Options) (*Client, error) {
	t.Helper()
	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", context.Background())

	obj, err := runtime.New(runtime.ToValue(NewClient), runtime.ToValue(rawURL), runtime.ToValue(opts))
	if err != nil {
		return nil, err
	}
	client, ok := obj.Export().(*Client)
	require.True(t, ok, "expected *Client export, got %T", obj.Export())
	t.Cleanup(client.Close)
	return client, nil
}

// thrown returns the message a client method throws into the JS runtime.
func thrown(fn func()) (message string) {
	defer func() {
		if r := recover(); r != nil {
			message = fmt.Sprint(r)
		}
	}()
	fn()
	return ""
}

func wsURL(server *httptest.Server) string {
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func TestTextAndBinaryRoundTrip(t *testing.T) {
	server := httptest.NewServer(echoHandler())
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, wsURL(server)+"/socket", Options{
		Protocols: []string{"chat"},
		Headers:   map[string]string{"Origin": "https://acme.test"},
	})
	require.NoError(t, err)

	require.Equal(t, "welcome", client.Receive(), "a message sent right after the handshake is not lost")
	require.Equal(t, "chat", client.Protocol)
	require.Equal(t, "echo", client.ResponseHeaders["X-Server"])

	client.Send("hello")
	require.Equal(t, "hello", client.Receive())

	client.SendHex("00ff10")
	require.Equal(t, "00ff10", client.ReceiveHex())
}

func TestServerCloseIsReported(t *testing.T) {
	server := httptest.NewServer(echoHandler())
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, wsURL(server), Options{})
	require.NoError(t, err)
	require.Equal(t, "welcome", client.Receive())

	client.Send("close-me")
	require.Contains(t, thrown(func() { client.Receive() }), "closed by server: 1001 bye")
}

func TestRejectedHandshake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, wsURL(server), Options{})
	require.NoError(t, err)
	message := thrown(client.Connect)
	require.Contains(t, message, "websocket handshake failed")
	require.Contains(t, message, "403")
}

func TestSecureWebSocket(t *testing.T) {
	server := httptest.NewTLSServer(echoHandler())
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, "wss"+strings.TrimPrefix(server.URL, "https"), Options{})
	require.NoError(t, err)
	require.Equal(t, "welcome", client.Receive())
	client.Send("over tls")
	require.Equal(t, "over tls", client.Receive())
}

func TestConstructorValidation(t *testing.T) {
	executionID := initExec(t, &types.Options{})
	for rawURL, want := range map[string]string{
		"":                   "cannot be empty",
		"http://acme.test/":  "ws:// or wss://",
		"ws:///path-only":    "host cannot be empty",
		"ws://%zz.test/sock": "invalid websocket url",
	} {
		t.Run(rawURL, func(t *testing.T) {
			_, err := newRuntimeClient(t, executionID, rawURL, Options{})
			require.ErrorContains(t, err, want)
		})
	}
}

func TestNetworkPolicyDeniesHost(t *testing.T) {
	executionID := initExec(t, &types.Options{ExcludeTargets: []string{"127.0.0.1"}})

	_, err := newRuntimeClient(t, executionID, "ws://127.0.0.1:9/socket", Options{})
	require.ErrorContains(t, err, "network policy")
}

func TestHTTPProxy(t *testing.T) {
	server := httptest.NewServer(echoHandler())
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "http://")

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = proxyLn.Close() }()
	tunneled := make(chan string, 1)
	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		tunneled <- strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, conn) }()
		_, _ = io.Copy(conn, upstream)
	}()

	executionID := initExec(t, &types.Options{})
	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", context.WithValue(context.Background(), "proxyURL", "http://"+proxyLn.Addr().String())) //nolint:staticcheck
	obj, err := runtime.New(runtime.ToValue(NewClient), runtime.ToValue("ws://"+target+"/socket"))
	require.NoError(t, err)
	client := obj.Export().(*Client)
	defer client.Close()

	require.Equal(t, "welcome", client.Receive())
	require.Equal(t, "CONNECT "+target+" HTTP/1.1", <-tunneled)
}

func TestPingInsideFragmentedMessageIsAnswered(t *testing.T) {
	pong := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = ws.WriteFrame(conn, ws.NewFrame(ws.OpText, false, []byte("frag")))
		_ = ws.WriteFrame(conn, ws.NewPingFrame([]byte("mid")))
		_ = ws.WriteFrame(conn, ws.NewFrame(ws.OpContinuation, true, []byte("mented")))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		frame, err := ws.ReadFrame(conn)
		pong <- err == nil && frame.Header.OpCode == ws.OpPong
	}))
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, wsURL(server), Options{})
	require.NoError(t, err)
	require.Equal(t, "fragmented", client.Receive())
	require.True(t, <-pong, "a ping between fragments must be answered")
}

func TestServerCloseReleasesConnection(t *testing.T) {
	server := httptest.NewServer(echoHandler())
	defer server.Close()
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, wsURL(server), Options{})
	require.NoError(t, err)
	require.Equal(t, "welcome", client.Receive())
	client.Send("close-me")
	require.Contains(t, thrown(func() { client.Receive() }), "closed by server")
	require.Nil(t, client.conn, "the closed connection must be released")
}
