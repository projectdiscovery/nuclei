package contextargs

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/require"
)

func TestMetaInputHostname(t *testing.T) {
	for input, want := range map[string]string{
		"https://a.example:8443/path": "a.example",
		"a.example:8443":              "a.example",
		"a.example":                   "a.example",
		"http://[2001:db8::1]:80":     "2001:db8::1",
	} {
		require.Equal(t, want, (&MetaInput{Input: input}).Hostname(), input)
	}
}

func TestWithCustomIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("pinned"))
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// pinned.test does not resolve: only the pin can reach the listener
	opts := fastdialer.DefaultOptions
	opts.HostsFile = false
	opts.ResolversFile = false
	opts.BaseResolvers = []string{"127.0.0.1:1"}
	opts.MaxRetries = 1
	opts.DialerTimeout = 2 * time.Second
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	input := &MetaInput{Input: "https://pinned.test:" + port, CustomIP: "127.0.0.1"}
	conn, err := fd.Dial(WithCustomIP(context.Background(), input), "tcp", net.JoinHostPort("pinned.test", port))
	require.NoError(t, err)
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, "pinned", string(data))
	_ = conn.Close()

	ctx := context.Background()
	require.Equal(t, ctx, WithCustomIP(ctx, &MetaInput{Input: "https://pinned.test"}), "an input without ip leaves ctx as is")
}
