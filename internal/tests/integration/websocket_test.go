//go:build integration
// +build integration

package integration_test

import (
	"net"
	"strings"
	"testing"

	"github.com/gobwas/ws/wsutil"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestWebSocket(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		connHandler := func(conn net.Conn) {
			for {
				msg, op, err := wsutil.ReadClientData(conn)
				if err != nil {
					return
				}
				if string(msg) != "hello" {
					return
				}
				_ = wsutil.WriteServerMessage(conn, op, []byte("world"))
			}
		}
		server := testutils.NewWebsocketServer("", connHandler, func(origin string) bool { return true })
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/websocket/basic.yaml", strings.ReplaceAll(server.URL, "http", "ws"), suite.debug)
		if err != nil {
			t.Fatalf("basic websocket request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CSWSH", func(t *testing.T) {
		server := testutils.NewWebsocketServer("", func(conn net.Conn) {}, func(origin string) bool { return true })
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/websocket/cswsh.yaml", strings.ReplaceAll(server.URL, "http", "ws"), suite.debug)
		if err != nil {
			t.Fatalf("cswsh websocket request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NoCSWSH", func(t *testing.T) {
		server := testutils.NewWebsocketServer("", func(conn net.Conn) {}, func(origin string) bool { return origin == "https://google.com" })
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/websocket/no-cswsh.yaml", strings.ReplaceAll(server.URL, "http", "ws"), suite.debug)
		if err != nil {
			t.Fatalf("no-cswsh websocket request failed: %v", err)
		}
		if err := expectResultsCount(results, 0); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Path", func(t *testing.T) {
		server := testutils.NewWebsocketServer("/test", func(conn net.Conn) {}, func(origin string) bool { return origin == "https://google.com" })
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/websocket/path.yaml", strings.ReplaceAll(server.URL, "http", "ws"), suite.debug)
		if err != nil {
			t.Fatalf("path websocket request failed: %v", err)
		}
		if err := expectResultsCount(results, 0); err != nil {
			t.Fatal(err)
		}
	})
}
