//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/utils/reader"
)

func TestNetwork(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		errState := &capturedError{}
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "PING" {
				_, _ = conn.Write([]byte("PONG"))
				return
			}
			errState.Set(fmt.Errorf("invalid data received: %s", string(data)))
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/basic.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("basic network request failed: %v", err)
		}
		if err := errState.Err(); err != nil {
			t.Fatal(err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Hex", func(t *testing.T) {
		errState := &capturedError{}
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "PING" {
				_, _ = conn.Write([]byte("PONG"))
				return
			}
			errState.Set(fmt.Errorf("invalid data received: %s", string(data)))
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/hex.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("hex network request failed: %v", err)
		}
		if err := errState.Err(); err != nil {
			t.Fatal(err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MultiStep", func(t *testing.T) {
		errState := &capturedError{}
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 5, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "FIRST" {
				_, _ = conn.Write([]byte("PING"))
			}

			data, err = reader.ConnReadNWithTimeout(conn, 6, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "SECOND" {
				_, _ = conn.Write([]byte("PONG"))
			}
			_, _ = conn.Write([]byte("NUCLEI"))
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/multi-step.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("multi-step network request failed: %v", err)
		}
		if err := errState.Err(); err != nil {
			t.Fatal(err)
		}
		expectedCount := 1
		if suite.debug {
			expectedCount = 3
		}
		if err := expectResultsCount(results, expectedCount); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SelfContained", func(t *testing.T) {
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_, _ = conn.Write([]byte("Authentication successful"))
		})
		defer server.Close()

		templatePath := tempFixtureCopy(t, "protocols/network/self-contained.yaml", map[string]string{
			"127.0.0.1:5431": server.URL,
		})
		results, err := testutils.RunNucleiTemplateAndGetResults(templatePath, "", suite.debug, "-esc")
		if err != nil {
			t.Fatalf("self-contained network request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Variables", func(t *testing.T) {
		errState := &capturedError{}
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "PING" {
				_, _ = conn.Write([]byte("aGVsbG8="))
			}
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/variables.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("variables network request failed: %v", err)
		}
		if err := errState.Err(); err != nil {
			t.Fatal(err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SameAddress", func(t *testing.T) {
		errState := &capturedError{}
		server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err != nil {
				errState.Set(err)
				return
			}
			if string(data) == "PING" {
				_, _ = conn.Write([]byte("PONG"))
				return
			}
			errState.Set(fmt.Errorf("invalid data received: %s", string(data)))
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/same-address.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("same-address network request failed: %v", err)
		}
		if err := errState.Err(); err != nil {
			t.Fatal(err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NetworkPort", func(t *testing.T) {
		server := testutils.NewTCPServer(nil, 23846, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err == nil && string(data) == "PING" {
				_, _ = conn.Write([]byte("PONG"))
			}
		})
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/network-port.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("network-port template failed with template port: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}

		results, err = testutils.RunNucleiTemplateAndGetResults("protocols/network/network-port.yaml", strings.ReplaceAll(server.URL, "23846", "443"), suite.debug)
		if err != nil {
			t.Fatalf("network-port template failed with overridden input port: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}

		serverOverride := testutils.NewTCPServer(nil, 34567, func(conn net.Conn) {
			defer func() { _ = conn.Close() }()

			data, err := reader.ConnReadNWithTimeout(conn, 4, 5*time.Second)
			if err == nil && string(data) == "PING" {
				_, _ = conn.Write([]byte("PONG"))
			}
		})
		defer serverOverride.Close()

		results, err = testutils.RunNucleiTemplateAndGetResults("protocols/network/network-port.yaml", serverOverride.URL, suite.debug)
		if err != nil {
			t.Fatalf("network-port template failed with runtime override port: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NetHTTPS", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/net-https.yaml", "scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("network https request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NetHTTPSTimeout", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/network/net-https-timeout.yaml", "scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("network https timeout request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}
