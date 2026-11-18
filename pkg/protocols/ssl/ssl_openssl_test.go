package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
)

func selfSignedCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS counts the TLS handshakes that reach address.
func serveTLS(t *testing.T, address, name string, handshakes *atomic.Int32) string {
	t.Helper()
	listener, err := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{selfSignedCertificate(t, name)}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if conn.(*tls.Conn).Handshake() == nil {
					handshakes.Add(1)
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func TestSSLOpenSSLObeysNetworkPolicy(t *testing.T) {
	if !openssl.IsAvailable() {
		t.Skip("openssl binary is not installed")
	}
	addrs, err := net.LookupHost("localhost")
	if err != nil || len(addrs) < 2 {
		t.Skip("localhost does not resolve to both loopback addresses")
	}

	// The policy allows 127.0.0.1 and denies ::1, so localhost passes the
	// dial check. The openssl binary must not connect to ::1.
	var allowedHandshakes, deniedHandshakes atomic.Int32
	allowed := serveTLS(t, "127.0.0.1:0", "allowed", &allowedHandshakes)
	_, port, err := net.SplitHostPort(allowed)
	require.NoError(t, err)
	serveTLS(t, net.JoinHostPort("::1", port), "denied", &deniedHandshakes)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"::1"}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "ssl-openssl-policy"})
	executerOpts.IsMultiProtocol = true

	request := &Request{ID: "ssl-openssl-policy", Address: "{{Host}}:{{Port}}", ScanMode: "openssl"}
	require.NoError(t, request.Compile(executerOpts))
	// The scan resolves names with the fastdialer, not the system resolver. On
	// Windows the hosts file has no localhost entry, so the name does not resolve.
	if !resolvesToBothLoopbacks(request) {
		t.Skip("the scan dialer does not resolve localhost to both loopback addresses")
	}

	var event output.InternalEvent
	input := contextargs.NewWithInput(context.Background(), net.JoinHostPort("localhost", port))
	err = request.ExecuteWithResults(input, nil, nil, func(e *output.InternalWrappedEvent) {
		event = e.InternalEvent
	})
	require.NoError(t, err)
	require.Equal(t, "allowed", event["subject_cn"])
	require.Zero(t, deniedHandshakes.Load(), "openssl connected to a denied address")
}

func resolvesToBothLoopbacks(request *Request) bool {
	data, err := request.dialer.GetDNSData("localhost")
	if err != nil {
		return false
	}
	return slices.Contains(data.A, "127.0.0.1") && slices.Contains(data.AAAA, "::1")
}

func TestSSLOpenSSLLiteralIPObeysExecutionPolicy(t *testing.T) {
	if !openssl.IsAvailable() {
		t.Skip("openssl binary is not installed")
	}

	// The input pins ::1 as its custom ip, and a custom dialer with no deny
	// list would connect to it. The execution policy denies it, so the openssl
	// binary must not connect to it.
	var deniedHandshakes atomic.Int32
	denied := serveTLS(t, "[::1]:0", "denied", &deniedHandshakes)
	_, port, err := net.SplitHostPort(denied)
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"::1"}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "ssl-openssl-literal-ip"})
	executerOpts.IsMultiProtocol = true
	customDialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	t.Cleanup(customDialer.Close)
	executerOpts.CustomFastdialer = customDialer

	request := &Request{ID: "ssl-openssl-literal-ip", Address: "{{Host}}:{{Port}}", ScanMode: "openssl"}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), net.JoinHostPort("localhost", port))
	input.MetaInput.CustomIP = "::1"
	err = request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})
	require.Error(t, err)
	require.Zero(t, deniedHandshakes.Load(), "openssl connected to an address the execution policy denies")
}

func TestSSLOpenSSLCustomIPObeysNetworkPolicy(t *testing.T) {
	if !openssl.IsAvailable() {
		t.Skip("openssl binary is not installed")
	}

	// The input pins the denied address ::1 as its custom ip, so the request
	// skips the name lookup. The openssl binary must still not connect to it.
	var deniedHandshakes atomic.Int32
	denied := serveTLS(t, "[::1]:0", "denied", &deniedHandshakes)
	_, port, err := net.SplitHostPort(denied)
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"::1"}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "ssl-openssl-custom-ip"})
	executerOpts.IsMultiProtocol = true

	request := &Request{ID: "ssl-openssl-custom-ip", Address: "{{Host}}:{{Port}}", ScanMode: "openssl"}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), net.JoinHostPort("localhost", port))
	input.MetaInput.CustomIP = "::1"
	_ = request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})
	require.Zero(t, deniedHandshakes.Load(), "openssl connected to a denied custom ip")
}
