//go:build integration
// +build integration

package integration_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestSSL(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/basic.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("basic ssl request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("BasicZTLS", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/basic-ztls.yaml", server.URL, suite.debug, "-ztls")
		if err != nil {
			t.Fatalf("basic ztls request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CustomCipher", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/custom-cipher.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("custom cipher ssl request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CustomVersion", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/custom-version.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("custom version ssl request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("WithVars", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/ssl-with-vars.yaml", server.URL, suite.debug, "-V", "test=asdasdas")
		if err != nil {
			t.Fatalf("ssl with vars request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MultiReq", func(t *testing.T) {
		server := newTLSServer(t, &tls.Config{
			//nolint:staticcheck // SSLv3 is intentionally used for testing purposes.
			MinVersion: tls.VersionSSL30,
			MaxVersion: tls.VersionTLS11,
		})
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ssl/multi-req.yaml", server.URL, suite.debug, "-V")
		if err != nil {
			t.Fatalf("ssl multi request failed: %v", err)
		}
		if err := expectResultsCount(results, 2); err != nil {
			t.Fatal(err)
		}
	})
}

func newTLSServer(t *testing.T, config *tls.Config) *testutils.TCPServer {
	t.Helper()
	server := testutils.NewTCPServer(config, 0, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		data := make([]byte, 4)
		_, _ = conn.Read(data)
	})
	t.Cleanup(server.Close)
	return server
}
