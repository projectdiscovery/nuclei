package protocolstate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
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
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         d.proxyURL.Hostname(),
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
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
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}

// bufferedConn keeps bytes the proxy sent right after the CONNECT response.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
