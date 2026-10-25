package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// headlessProxy is a local loopback HTTP/CONNECT proxy that intercepts
// and enforces network policy on all network traffic initiated by the headless browser,
// including WebSocket handshakes (which bypass CDP request blocking in Chromium).
type headlessProxy struct {
	listener  net.Listener
	options   *types.Options
	closed    chan struct{}
	closeOnce sync.Once
}

// newHeadlessProxy creates and starts a loopback HTTP/CONNECT proxy for headless Chrome.
func newHeadlessProxy(options *types.Options) (*headlessProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not start headless proxy listener: %w", err)
	}

	p := &headlessProxy{
		listener: ln,
		options:  options,
		closed:   make(chan struct{}),
	}

	go p.serve()

	return p, nil
}

// Addr returns the listening address of the proxy (e.g. "127.0.0.1:54321").
func (p *headlessProxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Close terminates the proxy listener.
func (p *headlessProxy) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.closed)
		if p.listener != nil {
			err = p.listener.Close()
		}
	})
	return err
}

func (p *headlessProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
				return
			}
		}
		go p.handleConn(conn)
	}
}

func (p *headlessProxy) handleConn(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
	}()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Validate host against network policy
	executionId := ""
	if p.options != nil {
		executionId = p.options.ExecutionId
	}

	h := host
	if splitH, _, err := net.SplitHostPort(host); err == nil {
		h = splitH
	}
	canonH := protocolstate.CanonicalizeHost(h)

	if !protocolstate.IsHostAllowed(executionId, host) || !protocolstate.IsHostAllowed(executionId, canonH) {
		if req.Method == http.MethodConnect {
			_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		} else {
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Blocked by network policy")),
			}
			_ = resp.Write(clientConn)
		}
		return
	}

	// Handle CONNECT tunnel (for HTTPS and WebSocket handshakes).
	// Keep the buffered reader: the client hello is often already in it.
	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, reader, host)
		return
	}

	// Handle standard HTTP requests
	p.handleHTTP(clientConn, reader, req, host)
}

func (p *headlessProxy) dialTarget(target string) (net.Conn, error) {
	host := target
	port := "80"
	if h, pt, err := net.SplitHostPort(target); err == nil {
		host = h
		port = pt
	}
	canonHost := protocolstate.CanonicalizeHost(host)

	executionId := ""
	if p.options != nil {
		executionId = p.options.ExecutionId
	}

	if !protocolstate.IsHostAllowed(executionId, host) || !protocolstate.IsHostAllowed(executionId, canonHost) {
		return nil, fmt.Errorf("target %s blocked by network policy", target)
	}

	// Dial an address that was just checked. A later lookup of the name can
	// return a different, excluded address. A resolution failure refuses the
	// dial instead of connecting to whatever the name means a moment later.
	dialHost := canonHost
	if net.ParseIP(canonHost) == nil {
		ips, err := net.LookupIP(canonHost)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", canonHost, err)
		}
		var chosen net.IP
		for _, resolvedIP := range ips {
			canonIP := protocolstate.CanonicalizeHost(resolvedIP.String())
			if !protocolstate.IsHostAllowed(executionId, canonIP) {
				return nil, fmt.Errorf("target %s resolves to blocked IP %s", target, canonIP)
			}
			if chosen == nil {
				chosen = resolvedIP
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("resolve %s: no addresses", canonHost)
		}
		dialHost = chosen.String()
	}

	dialAddr := net.JoinHostPort(dialHost, port)

	// If upstream proxy is configured, route through it after validation
	if p.options != nil && p.options.AliveHttpProxy != "" {
		proxyURL, err := url.Parse(p.options.AliveHttpProxy)
		if err == nil {
			proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
			if err != nil {
				return nil, err
			}
			// CONNECT through upstream proxy with canonical address
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dialAddr, dialAddr)
			if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
				_ = proxyConn.Close()
				return nil, err
			}
			resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
			if err != nil || resp.StatusCode != http.StatusOK {
				_ = proxyConn.Close()
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("upstream proxy CONNECT returned %d", resp.StatusCode)
			}
			return proxyConn, nil
		}
	}

	// Use fastdialer if available for network policy compliance and DNS caching
	if dialer := protocolstate.GetDialersWithId(executionId); dialer != nil && dialer.Fastdialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return dialer.Fastdialer.Dial(ctx, "tcp", dialAddr)
	}

	return net.DialTimeout("tcp", dialAddr, 10*time.Second)
}

func (p *headlessProxy) handleConnect(clientConn net.Conn, clientReader *bufio.Reader, target string) {
	destConn, err := p.dialTarget(target)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() {
		_ = destConn.Close()
	}()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Tunnel traffic bidirectionally. clientReader carries bytes already
	// read with the CONNECT request. One direction ending is enough to
	// tear the tunnel down.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(destConn, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()
	<-done
}

func (p *headlessProxy) handleHTTP(clientConn net.Conn, clientReader *bufio.Reader, req *http.Request, host string) {
	destHost := host
	if !strings.Contains(destHost, ":") {
		destHost += ":80"
	}

	destConn, err := p.dialTarget(destHost)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() {
		_ = destConn.Close()
	}()

	if err := req.Write(destConn); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(destConn, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()
	<-done
}
