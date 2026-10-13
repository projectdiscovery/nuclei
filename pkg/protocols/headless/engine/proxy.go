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
	listener net.Listener
	options  *types.Options
	closed   chan struct{}
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
	defer clientConn.Close()

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

	if !protocolstate.IsHostAllowed(executionId, host) {
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

	// Handle CONNECT tunnel (for HTTPS and WebSocket handshakes)
	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, host)
		return
	}

	// Handle standard HTTP requests
	p.handleHTTP(clientConn, reader, req, host)
}

func (p *headlessProxy) dialTarget(target string) (net.Conn, error) {
	// If upstream proxy is configured, route through it
	if p.options != nil && p.options.AliveHttpProxy != "" {
		proxyURL, err := url.Parse(p.options.AliveHttpProxy)
		if err == nil {
			proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
			if err != nil {
				return nil, err
			}
			// CONNECT through upstream proxy
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
				proxyConn.Close()
				return nil, err
			}
			resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
			if err != nil || resp.StatusCode != http.StatusOK {
				proxyConn.Close()
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("upstream proxy CONNECT returned %d", resp.StatusCode)
			}
			return proxyConn, nil
		}
	}

	// Use fastdialer if available for network policy compliance and DNS caching
	var executionId string
	if p.options != nil {
		executionId = p.options.ExecutionId
	}
	if dialer := protocolstate.GetDialersWithId(executionId); dialer != nil && dialer.Fastdialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return dialer.Fastdialer.Dial(ctx, "tcp", target)
	}

	return net.DialTimeout("tcp", target, 10*time.Second)
}

func (p *headlessProxy) handleConnect(clientConn net.Conn, target string) {
	destConn, err := p.dialTarget(target)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Tunnel traffic bidirectionally
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(destConn, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, destConn)
		errc <- err
	}()
	<-errc
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
	defer destConn.Close()

	if err := req.Write(destConn); err != nil {
		return
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(destConn, clientReader)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, destConn)
		errc <- err
	}()
	<-errc
}
