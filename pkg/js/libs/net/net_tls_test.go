package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// newALPNServer starts a TLS server that accepts h2 and http/1.1 and records
// the SNI of the last ClientHello.
func newALPNServer(t *testing.T) (addr string, lastSNI func() string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var mu sync.Mutex
	var sni string
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			sni = hello.ServerName
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return sni
	}
}

func newTLSTestContext(t *testing.T) context.Context {
	t.Helper()
	opts := &types.Options{ExecutionId: "net-tls-" + t.Name()}
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	return context.WithValue(context.Background(), "executionId", opts.ExecutionId) // nolint: staticcheck
}

func TestTLSConfigFromOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config, err := tlsConfigFromOptions("example.com:443", TLSOptions{})
		require.NoError(t, err)
		require.Equal(t, uint16(tls.VersionTLS10), config.MinVersion)
		require.Zero(t, config.MaxVersion)
		require.Nil(t, config.NextProtos)
		require.Equal(t, "example.com", config.ServerName)
		require.True(t, config.InsecureSkipVerify)
	})

	t.Run("custom", func(t *testing.T) {
		alpn := []string{"h2"}
		config, err := tlsConfigFromOptions("example.com:443", TLSOptions{
			ALPN:       alpn,
			MinVersion: "TLS12",
			MaxVersion: " tls13 ",
			ServerName: "sni.example",
		})
		require.NoError(t, err)
		require.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
		require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
		require.Equal(t, []string{"h2"}, config.NextProtos)
		require.Equal(t, "sni.example", config.ServerName)

		// the config must not alias the caller's slice
		alpn[0] = "changed"
		require.Equal(t, []string{"h2"}, config.NextProtos)
	})

	t.Run("invalid version", func(t *testing.T) {
		_, err := tlsConfigFromOptions("example.com:443", TLSOptions{MaxVersion: "ssl3"})
		require.ErrorContains(t, err, "invalid TLS version")
	})

	t.Run("max below min", func(t *testing.T) {
		_, err := tlsConfigFromOptions("example.com:443", TLSOptions{MinVersion: "tls13", MaxVersion: "tls12"})
		require.ErrorContains(t, err, "lower than MinVersion")
	})
}

func TestOpenTLSWithOptions(t *testing.T) {
	addr, lastSNI := newALPNServer(t)
	ctx := newTLSTestContext(t)

	cases := []struct {
		name  string
		opts  TLSOptions
		proto string
	}{
		{name: "h2 preferred", opts: TLSOptions{ALPN: []string{"h2", "http/1.1"}}, proto: "h2"},
		{name: "h2 only", opts: TLSOptions{ALPN: []string{"h2"}}, proto: "h2"},
		{name: "http1 only", opts: TLSOptions{ALPN: []string{"http/1.1"}}, proto: "http/1.1"},
		{name: "no alpn", opts: TLSOptions{}, proto: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := OpenTLSWithOptions(ctx, "tcp", addr, tc.opts)
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			require.Equal(t, tc.proto, conn.NegotiatedProtocol())
			require.Equal(t, "TLS 1.3", conn.TLSVersion())
			require.NotEmpty(t, conn.CipherSuite())
		})
	}

	t.Run("max version", func(t *testing.T) {
		conn, err := OpenTLSWithOptions(ctx, "tcp", addr, TLSOptions{ALPN: []string{"h2"}, MaxVersion: "tls12"})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.Equal(t, "TLS 1.2", conn.TLSVersion())
		require.Equal(t, "h2", conn.NegotiatedProtocol())
	})

	t.Run("server name", func(t *testing.T) {
		conn, err := OpenTLSWithOptions(ctx, "tcp", addr, TLSOptions{ServerName: "sni.example"})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.Equal(t, "sni.example", lastSNI())
	})

	t.Run("invalid options fail before dialing", func(t *testing.T) {
		_, err := OpenTLSWithOptions(ctx, "tcp", addr, TLSOptions{MinVersion: "bogus"})
		require.ErrorContains(t, err, "invalid TLS version")
	})

	t.Run("OpenTLS keeps sending no alpn", func(t *testing.T) {
		conn, err := OpenTLS(ctx, "tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.Empty(t, conn.NegotiatedProtocol())
		require.NotEmpty(t, conn.TLSVersion())
	})

	t.Run("plain connection has no tls state", func(t *testing.T) {
		conn, err := Open(ctx, "tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.Empty(t, conn.NegotiatedProtocol())
		require.Empty(t, conn.TLSVersion())
		require.Empty(t, conn.CipherSuite())
	})
}

func TestOpenTLSWithOptionsThroughProxy(t *testing.T) {
	addr, _ := newALPNServer(t)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxyLn.Close() })
	go func() {
		for {
			client, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer func() { _ = client.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(client))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(upstream, client) }()
				_, _ = io.Copy(client, upstream)
			}(client)
		}
	}()

	ctx := newTLSTestContext(t)
	ctx = context.WithValue(ctx, "proxyURL", "http://"+proxyLn.Addr().String()) // nolint: staticcheck

	conn, err := OpenTLSWithOptions(ctx, "tcp", addr, TLSOptions{ALPN: []string{"h2"}})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Equal(t, "h2", conn.NegotiatedProtocol())
}
