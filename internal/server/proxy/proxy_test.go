package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

type captured struct {
	rawHTTP   string
	targetURL string
}

// newTestProxy returns a proxy served over a local listener along with the
// requests it mirrors into the scanner.
func newTestProxy(t *testing.T, options *Options) (*Proxy, *url.URL, <-chan captured) {
	t.Helper()

	mirrored := make(chan captured, 8)
	options.CADir = t.TempDir()
	options.Submit = func(rawHTTP, targetURL string) bool {
		mirrored <- captured{rawHTTP: rawHTTP, targetURL: targetURL}
		return true
	}
	if options.Address == "" {
		options.Address = "127.0.0.1:0"
	}

	instance, err := New(options)
	require.NoError(t, err)

	frontend := httptest.NewServer(instance.server.Handler)
	t.Cleanup(frontend.Close)

	proxyURL, err := url.Parse(frontend.URL)
	require.NoError(t, err)
	return instance, proxyURL, mirrored
}

// skipInstance drops the proxy handle for tests that only drive it over HTTP.
func skipInstance(_ *Proxy, proxyURL *url.URL, mirrored <-chan captured) (*url.URL, <-chan captured) {
	return proxyURL, mirrored
}

func clientThrough(proxyURL *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

func TestProxyForwardsAndMirrorsRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	proxyURL, mirrored := skipInstance(newTestProxy(t, &Options{}))

	resp, err := clientThrough(proxyURL).Post(upstream.URL+"/login?next=/admin", "application/json", strings.NewReader(`{"user":"admin"}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "upstream-body", string(body), "proxy must forward the upstream response untouched")

	got := <-mirrored
	require.Equal(t, upstream.URL+"/login?next=/admin", got.targetURL)

	// The scanner consumes the mirrored traffic through this parser, so the
	// capture is only useful if it round-trips.
	parsed, err := types.ParseRawRequestWithURL(got.rawHTTP, got.targetURL)
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, parsed.Request.Method)
	require.Equal(t, `{"user":"admin"}`, parsed.Request.Body)
	require.Equal(t, "/login", parsed.URL.Path)
}

func TestProxyRequiresAuthWhenConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	proxyURL, mirrored := skipInstance(newTestProxy(t, &Options{Username: "nuclei", Password: "s3cret"}))

	resp, err := clientThrough(proxyURL).Get(upstream.URL + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Proxy-Authenticate"), "Basic")
	require.Empty(t, mirrored, "an unauthenticated request must not reach the scanner")

	authenticated := proxyURL
	authenticated.User = url.UserPassword("nuclei", "s3cret")
	resp, err = clientThrough(authenticated).Get(upstream.URL + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, upstream.URL+"/", (<-mirrored).targetURL)
}

func TestProxyRejectsWrongCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()

	proxyURL, _ := skipInstance(newTestProxy(t, &Options{Username: "nuclei", Password: "s3cret"}))
	proxyURL.User = url.UserPassword("nuclei", "wrong")

	resp, err := clientThrough(proxyURL).Get(upstream.URL + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
}

func TestNewRefusesUnauthenticatedNonLoopbackBind(t *testing.T) {
	for _, address := range []string{"0.0.0.0:9056", "192.0.2.10:9056", ":9056"} {
		_, err := New(&Options{
			Address: address,
			CADir:   t.TempDir(),
			Submit:  func(string, string) bool { return true },
		})
		require.ErrorContains(t, err, "refusing to bind", address)
	}
}

func TestNewAllowsLoopbackAndAuthenticatedBinds(t *testing.T) {
	for _, options := range []*Options{
		{Address: "127.0.0.1:9056"},
		{Address: "localhost:9056"},
		{Address: "[::1]:9056"},
		{Address: "0.0.0.0:9056", Username: "nuclei", Password: "s3cret"},
	} {
		options.CADir = t.TempDir()
		options.Submit = func(string, string) bool { return true }
		_, err := New(options)
		require.NoError(t, err, options.Address)
	}
}

func TestNewRequiresBothAuthHalves(t *testing.T) {
	_, err := New(&Options{
		Address:  "127.0.0.1:9056",
		CADir:    t.TempDir(),
		Username: "nuclei",
		Submit:   func(string, string) bool { return true },
	})
	require.ErrorContains(t, err, "both a username and a password")
}

func TestParseAuth(t *testing.T) {
	username, password, err := ParseAuth("nuclei:s3cret")
	require.NoError(t, err)
	require.Equal(t, "nuclei", username)
	require.Equal(t, "s3cret", password)

	username, password, err = ParseAuth("")
	require.NoError(t, err)
	require.Empty(t, username)
	require.Empty(t, password)

	for _, invalid := range []string{"nuclei", ":s3cret", "nuclei:"} {
		_, _, err := ParseAuth(invalid)
		require.ErrorContains(t, err, "user:pass", invalid)
	}
}

func TestCaptureRequestSkipsUnboundedBody(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader("payload"))
	require.NoError(t, err)
	request.ContentLength = maxCapturedBodySize + 1

	_, ok := captureRequest(request)
	require.False(t, ok, "an oversized body must not be buffered")

	request.ContentLength = int64(len("payload"))
	raw, ok := captureRequest(request)
	require.True(t, ok)
	require.Contains(t, raw, "payload")
}

func TestCaptureRequestLeavesForwardedRequestIntact(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader("user=admin"))
	require.NoError(t, err)

	raw, ok := captureRequest(request)
	require.True(t, ok)
	require.Contains(t, raw, "user=admin")

	// The forwarded request still has to be readable after being mirrored.
	forwarded, err := io.ReadAll(request.Body)
	require.NoError(t, err)
	require.Equal(t, "user=admin", string(forwarded))
}

func TestCaptureRequestDropsProxyCredentials(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	request.RequestURI = "http://example.com/" // absolute form, as a proxy receives it
	request.Header.Set("Proxy-Authorization", "Basic bnVjbGVpOnMzY3JldA==")
	request.Header.Set("Proxy-Connection", "keep-alive")
	request.Header.Set("Authorization", "Bearer target-token")

	raw, ok := captureRequest(request)
	require.True(t, ok)
	require.NotContains(t, raw, "Proxy-Authorization", "the proxy credential must never reach the scanner")
	require.NotContains(t, raw, "bnVjbGVpOnMzY3JldA==")
	require.NotContains(t, raw, "Proxy-Connection")
	require.Contains(t, raw, "Bearer target-token", "the target's own credentials must be preserved")
	require.True(t, strings.HasPrefix(raw, "GET / HTTP/1.1"), "request line must be origin form, got %q", raw)
}

func TestCaptureRequestDropsHopByHopHeaders(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	request.Header.Set("Connection", "close, X-Proxy-Debug")
	request.Header.Set("X-Proxy-Debug", "1")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("TE", "trailers")
	request.Header.Set("X-Custom", "keep")

	raw, ok := captureRequest(request)
	require.True(t, ok)
	require.NotContains(t, raw, "X-Proxy-Debug")
	require.NotContains(t, raw, "Keep-Alive")
	require.NotContains(t, raw, "TE:")
	require.NotContains(t, raw, "Connection:")
	require.Contains(t, raw, "X-Custom: keep")
}

func TestNewRejectsInvalidForwardProxy(t *testing.T) {
	_, err := New(&Options{
		Address:      "127.0.0.1:9056",
		CADir:        t.TempDir(),
		ForwardProxy: "://bad",
		Submit:       func(string, string) bool { return true },
	})
	require.ErrorContains(t, err, "forward proxy")
}

func TestCaptureRequestRejectsNonHTTPScheme(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	request.URL.Scheme = "ftp"

	_, ok := captureRequest(request)
	require.False(t, ok)
}

// A client only sends Proxy-Authorization on CONNECT, so requests inside an
// established tunnel must not be challenged again.
func TestProxyAuthorizesTunnelOnceOnConnect(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	instance, proxyURL, mirrored := newTestProxy(t, &Options{Username: "nuclei", Password: "s3cret"})
	proxyURL.User = url.UserPassword("nuclei", "s3cret")

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(instance.CertPEM()))
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	resp, err := client.Get(upstream.URL + "/admin?id=1")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "a request inside an authorized tunnel must not be challenged")
	require.Equal(t, "upstream-body", string(body))

	got := <-mirrored
	require.Equal(t, upstream.URL+"/admin?id=1", got.targetURL)
	require.True(t, strings.HasPrefix(got.rawHTTP, "GET /admin?id=1 HTTP/1.1"), "got %q", got.rawHTTP)
}

func TestProxyChallengesUnauthenticatedConnect(t *testing.T) {
	_, proxyURL, _ := newTestProxy(t, &Options{Username: "nuclei", Password: "s3cret"})

	conn, err := net.Dial("tcp", proxyURL.Host)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// A malformed status line leaves a browser unable to prompt for credentials.
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Equal(t, 1, resp.ProtoMajor)
	require.Equal(t, 1, resp.ProtoMinor)
	require.Contains(t, resp.Header.Get("Proxy-Authenticate"), "Basic")
}

func TestProxyPassesThroughExcludedHostsWithoutMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	instance, proxyURL, mirrored := newTestProxy(t, &Options{
		Intercept: func(host string) bool {
			return host != upstreamURL.Host
		},
	})

	// Trust only the upstream certificate. An intercepted connection is
	// signed by the nuclei CA and would fail this handshake.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12},
	}}
	resp, err := client.Get(upstream.URL + "/secret")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "upstream-body", string(body))
	require.True(t, resp.TLS.PeerCertificates[0].Equal(upstream.Certificate()),
		"pass-through must present the target certificate, not a nuclei-minted one")

	require.Equal(t, int64(1), instance.Stats().TunnelsPassedThrough)
	require.Zero(t, instance.Stats().Intercepted)
	require.Empty(t, mirrored)
}
