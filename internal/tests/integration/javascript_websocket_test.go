//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// startWebSocketEchoServer starts a WebSocket server on a random loopback port
// that accepts the "chat" subprotocol, greets, then echoes every message.
func startWebSocketEchoServer() (string, func(), error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("websocket listen: %w", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := ws.HTTPUpgrader{Protocol: func(protocol string) bool { return protocol == "chat" }}
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
			if err := wsutil.WriteServerMessage(conn, op, payload); err != nil {
				return
			}
		}
	})}
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), func() { _ = srv.Close() }, nil
}

// javascriptWebSocketEcho exercises the nuclei/websocket library end to end
// against a real WebSocket server.
type javascriptWebSocketEcho struct{}

func (j *javascriptWebSocketEcho) Execute(filePath string) error {
	address, stop, err := startWebSocketEchoServer()
	if err != nil {
		return err
	}
	defer stop()

	results, err := runSignedNucleiTemplateAndGetResults(filePath, address, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// javascriptWebSocketDenied asserts the nuclei/websocket library refuses a host
// on the exclude list (network-policy enforcement) before connecting.
type javascriptWebSocketDenied struct{}

func (j *javascriptWebSocketDenied) Execute(filePath string) error {
	results, err := runSignedNucleiTemplateAndGetResults(filePath, "127.0.0.1", debug, "-eh", "203.0.113.10")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
