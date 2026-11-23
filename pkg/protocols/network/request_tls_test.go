package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

const (
	tlsHostTemplate = "tls://" + addressTemplate
	// tlsData is long enough for a TLS server to read a record header from, so
	// that it fails the handshake of a plain request without waiting for more.
	tlsData = "hello"
)

// tlsServer counts the connections of a server that accepts only TLS.
type tlsServer struct {
	address string
	// handshakes counts the TLS connections it answered, and plain counts the
	// connections that failed the handshake.
	handshakes atomic.Int32
	plain      atomic.Int32
}

// listenTLS serves loopback connections that speak TLS. It reads the request
// of each one and writes okReply. A connection that fails the handshake, as a
// plain request does, counts in plain.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func listenTLS(t *testing.T) *tlsServer {
	t.Helper()

	// The certificate is the one httptest serves; the server is not used.
	certificates := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certificates.Close)

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	//nolint:exhaustruct // the other fields keep their defaults
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certificates.TLS.Certificates,
	}
	server := &tlsServer{address: listener.Addr().String()}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				secured := tls.Server(conn, config)

				err := secured.HandshakeContext(t.Context())
				if err != nil {
					server.plain.Add(1)

					return
				}

				server.handshakes.Add(1)

				_, _ = secured.Read(make([]byte, 16))
				_, _ = secured.Write([]byte(okReply))
			}()
		}
	}()

	return server
}

// A plain entry and a tls:// entry for the same address are different
// requests, so the second is not skipped as a duplicate of the first (#8263).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestTLSEntryIsNotDuplicateOfPlainEntry(t *testing.T) {
	t.Run("one port", func(t *testing.T) {
		server := listenTLS(t)
		request := &Request{
			Address:   []string{addressTemplate, tlsHostTemplate},
			Inputs:    []*Input{{Data: tlsData}},
			Operators: wordMatcher(okReply),
		}
		compileWithCache(t, request)
		progress := countRequests(request)

		matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), server.address))

		require.NoError(t, err)
		require.Equal(t, 1, matches)
		require.Equal(t, int32(1), server.handshakes.Load())
		require.Equal(t, int32(1), server.plain.Load())
		require.Equal(t, int64(2), progress.requests.Load())
		require.Zero(t, progress.errors.Load())
	})

	// A plain entry after a tls:// one is still plain.
	t.Run("one port with the tls entry first", func(t *testing.T) {
		server := listenTLS(t)
		request := &Request{
			Address:   []string{tlsHostTemplate, addressTemplate},
			Inputs:    []*Input{{Data: tlsData}},
			Operators: wordMatcher(okReply),
		}
		compileWithCache(t, request)
		progress := countRequests(request)

		matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), server.address))

		require.NoError(t, err)
		require.Equal(t, 1, matches)
		require.Equal(t, int32(1), server.handshakes.Load())
		require.Equal(t, int32(1), server.plain.Load())
		require.Equal(t, int64(2), progress.requests.Load())
		require.Zero(t, progress.errors.Load())
	})

	t.Run("two ports", func(t *testing.T) {
		first := listenTLS(t)
		second := listenTLS(t)
		request := &Request{
			Address:   []string{addressTemplate, tlsHostTemplate},
			Port:      portsOf(t, first.address, second.address),
			Inputs:    []*Input{{Data: tlsData}},
			Operators: wordMatcher(okReply),
		}
		compileWithCache(t, request)
		progress := countRequests(request)

		matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), "127.0.0.1"))

		require.NoError(t, err)
		require.Equal(t, 2, matches)
		// The check for open ports also connects without TLS, so the plain
		// connections of each server are not counted.
		require.Equal(t, int32(1), first.handshakes.Load())
		require.Equal(t, int32(1), second.handshakes.Load())
		require.Equal(t, int64(4), progress.requests.Load())
		require.Zero(t, progress.errors.Load())
	})
}

// Two entries that dial the same way are still one request (#3821).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestSameTLSEntriesAreDuplicates(t *testing.T) {
	server := listenTLS(t)
	request := &Request{
		Address:   []string{tlsHostTemplate, "tls://" + hostPortTemplate},
		Inputs:    []*Input{{Data: tlsData}},
		Operators: wordMatcher(okReply),
	}
	compileWithCache(t, request)
	progress := countRequests(request)

	matches, err := executeMatching(request, contextargs.NewWithInput(context.Background(), server.address))

	require.NoError(t, err)
	require.Equal(t, 1, matches)
	require.Equal(t, int32(1), server.handshakes.Load())
	require.Zero(t, server.plain.Load())
	require.Equal(t, int64(2), progress.requests.Load())
	require.Zero(t, progress.errors.Load())
}
