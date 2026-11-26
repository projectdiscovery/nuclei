package protocolstate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// httpConnectDialer tunnels TCP connections through an HTTP(S) proxy using
// CONNECT, so protocols that speak raw TCP or TLS can honor an http -proxy.
type httpConnectDialer struct {
	proxyURL *url.URL
	forward  proxy.ContextDialer
	timeout  time.Duration
	// tlsConfig overrides the TLS settings used to talk to an https proxy. It
	// is nil outside tests, which verifies the proxy against the system roots.
	tlsConfig *tls.Config
}

var (
	_ proxy.Dialer        = &httpConnectDialer{}
	_ proxy.ContextDialer = &httpConnectDialer{}
)

func newHTTPConnectDialer(rawURL string, forward proxy.ContextDialer, timeout time.Duration) (*httpConnectDialer, error) {
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("proxy URL has no host")
	}
	return &httpConnectDialer{proxyURL: proxyURL, forward: forward, timeout: timeout}, nil
}

func (d *httpConnectDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *httpConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("http proxy cannot tunnel %s", network)
	}

	proxyAddr := d.proxyURL.Host
	if d.proxyURL.Port() == "" {
		port := "80"
		if d.proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(d.proxyURL.Hostname(), port)
	}

	conn, err := d.forward.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to proxy %s: %w", proxyAddr, err)
	}

	var deadline time.Time
	if d.timeout > 0 {
		deadline = time.Now().Add(d.timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	if d.proxyURL.Scheme == "https" {
		// verify the proxy: Proxy-Authorization is sent over this connection
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if d.tlsConfig != nil {
			cfg = d.tlsConfig.Clone()
		}
		cfg.ServerName = d.proxyURL.Hostname()
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("could not establish TLS with proxy %s: %w", proxyAddr, err)
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if user := d.proxyURL.User; user != nil {
		password, _ := user.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("could not send CONNECT to proxy %s: %w", proxyAddr, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("could not read CONNECT response from proxy %s: %w", proxyAddr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyAddr, address, resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	tunnel := &tunnelConn{Conn: conn, remote: tunnelAddr(address)}
	if br.Buffered() > 0 {
		// keep bytes the proxy sent right after the CONNECT response
		tunnel.reader = br
	}
	return tunnel, nil
}

// tunnelAddr turns a dial address into the net.Addr of the tunneled target.
func tunnelAddr(address string) net.Addr {
	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return net.TCPAddrFromAddrPort(addrPort)
	}
	return hostAddr(address)
}

// hostAddr is a target given by name, which is not resolved here.
type hostAddr string

func (hostAddr) Network() string  { return "tcp" }
func (a hostAddr) String() string { return string(a) }

// tunnelConn reports the tunneled target, not the proxy, as the remote
// address, so callers that record it (dial history, tls results) see the host
// they asked for. It also replays bytes buffered after the CONNECT response.
type tunnelConn struct {
	net.Conn
	remote net.Addr
	reader *bufio.Reader
}

func (c *tunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *tunnelConn) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}
