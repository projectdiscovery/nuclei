package engine

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHeadlessProxy_BlocksExcludedHosts(t *testing.T) {
	// 1. Setup blocked TCP server
	blockedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = blockedLn.Close()
	}()

	var blockedHits atomic.Int32
	go func() {
		for {
			conn, err := blockedLn.Accept()
			if err != nil {
				return
			}
			blockedHits.Add(1)
			_ = conn.Close()
		}
	}()

	blockedPort := blockedLn.Addr().(*net.TCPAddr).Port

	// 2. Setup allowed TCP server
	allowedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = allowedLn.Close()
	}()

	var allowedHits atomic.Int32
	go func() {
		for {
			conn, err := allowedLn.Accept()
			if err != nil {
				return
			}
			allowedHits.Add(1)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			_ = conn.Close()
		}
	}()

	allowedPort := allowedLn.Addr().(*net.TCPAddr).Port

	// 3. Configure network policy with blocked target
	execID := fmt.Sprintf("test-proxy-%d", time.Now().UnixNano())
	opts := &types.Options{
		ExecutionId: execID,
		ExcludeTargets: []string{
			fmt.Sprintf("127.0.0.1:%d", blockedPort),
		},
	}

	np, err := networkpolicy.New(networkpolicy.Options{
		DenyList: []string{
			fmt.Sprintf("127.0.0.1:%d", blockedPort),
		},
	})
	require.NoError(t, err)

	d := &protocolstate.Dialers{
		NetworkPolicy:  np,
		ExcludeTargets: opts.ExcludeTargets,
	}
	_ = protocolstate.Init(opts)
	// Override with our strict policy for this test
	if existing := protocolstate.GetDialersWithId(execID); existing != nil {
		existing.NetworkPolicy = np
	} else {
		// Mock dialer in case Init didn't populate for test
		_ = d
	}

	// 4. Start headless proxy
	proxy, err := newHeadlessProxy(opts)
	require.NoError(t, err)
	defer func() {
		_ = proxy.Close()
	}()

	// 5. Test CONNECT to blocked destination
	clientConn, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	defer func() {
		_ = clientConn.Close()
	}()

	connectReq := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", blockedPort, blockedPort)
	_, err = clientConn.Write([]byte(connectReq))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Zero(t, blockedHits.Load(), "blocked host must never receive connection")

	// 6. Test GET to blocked destination
	clientConn2, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	defer func() {
		_ = clientConn2.Close()
	}()

	getReq := fmt.Sprintf("GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", blockedPort, blockedPort)
	_, err = clientConn2.Write([]byte(getReq))
	require.NoError(t, err)

	reader2 := bufio.NewReader(clientConn2)
	resp2, err := http.ReadResponse(reader2, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
	require.Zero(t, blockedHits.Load(), "blocked host must never receive connection")

	// 7. Test CONNECT to allowed destination
	clientConn3, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	defer func() {
		_ = clientConn3.Close()
	}()

	allowedReq := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", allowedPort, allowedPort)
	_, err = clientConn3.Write([]byte(allowedReq))
	require.NoError(t, err)

	reader3 := bufio.NewReader(clientConn3)
	resp3, err := http.ReadResponse(reader3, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp3.StatusCode)

	// Send data through tunnel
	_, err = clientConn3.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, _ := clientConn3.Read(buf)
	require.Contains(t, string(buf[:n]), "200 OK")
	require.Equal(t, int32(1), allowedHits.Load())
}

func TestHeadlessProxy_RealChromeWebSocketEndToEnd(t *testing.T) {
	// 1. Setup blocked WebSocket server
	blockedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = blockedLn.Close()
	}()

	var blockedHits atomic.Int32
	go func() {
		for {
			conn, err := blockedLn.Accept()
			if err != nil {
				return
			}
			blockedHits.Add(1)
			_ = conn.Close()
		}
	}()

	blockedPort := blockedLn.Addr().(*net.TCPAddr).Port

	// 2. Configure network policy with blocked target
	execID := fmt.Sprintf("test-chrome-ws-%d", time.Now().UnixNano())
	opts := &types.Options{
		ExecutionId: execID,
		ExcludeTargets: []string{
			fmt.Sprintf("127.0.0.1:%d", blockedPort),
		},
		ShowBrowser: false,
	}

	np, err := networkpolicy.New(networkpolicy.Options{
		DenyList: []string{
			fmt.Sprintf("127.0.0.1:%d", blockedPort),
		},
	})
	require.NoError(t, err)

	_ = protocolstate.Init(opts)
	if existing := protocolstate.GetDialersWithId(execID); existing != nil {
		existing.NetworkPolicy = np
	}

	// 3. Start headless proxy
	proxy, err := newHeadlessProxy(opts)
	require.NoError(t, err)
	defer func() {
		_ = proxy.Close()
	}()

	// 4. Launch Chrome with proxy and <-loopback>
	chromeLauncher := launcher.New().
		Leakless(false).
		Headless(true).
		Proxy(proxy.Addr()).
		Set("proxy-bypass-list", "<-loopback>")

	if bin, hasChrome := launcher.LookPath(); hasChrome {
		chromeLauncher.Bin(bin)
	} else {
		t.Skip("Chrome binary not found on system, skipping end-to-end browser test")
	}

	controlURL, err := chromeLauncher.Launch()
	if err != nil {
		t.Skipf("Chrome launch failed in test environment: %v", err)
	}

	browser := rod.New().ControlURL(controlURL).MustConnect()
	defer func() {
		_ = browser.Close()
	}()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	require.NoError(t, err)
	defer func() {
		_ = page.Close()
	}()

	script := fmt.Sprintf(`() => new Promise((resolve) => {
		try {
			const ws = new WebSocket("ws://127.0.0.1:%d/");
			ws.onopen = () => resolve("OPEN");
			ws.onerror = () => resolve("ERROR");
			setTimeout(() => resolve("TIMEOUT"), 3000);
		} catch (err) {
			resolve("ERROR");
		}
	})`, blockedPort)

	res, err := page.Eval(script)
	require.NoError(t, err)
	require.Equal(t, "ERROR", res.Value.String())
	require.Zero(t, blockedHits.Load(), "blocked WebSocket server must never receive connections from Chrome")
}

func TestHeadlessProxy_IPv4MappedIPv6WithUpstreamProxy(t *testing.T) {
	// 1. Setup mock upstream HTTP proxy
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = upstreamLn.Close()
	}()

	var upstreamHits atomic.Int32
	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			upstreamHits.Add(1)
			_ = conn.Close()
		}
	}()

	// 2. Configure options with upstream proxy and restricted local network / excluded 127.0.0.1
	execID := fmt.Sprintf("test-mapped-proxy-%d", time.Now().UnixNano())
	opts := &types.Options{
		ExecutionId:                execID,
		AliveHttpProxy:             "http://" + upstreamLn.Addr().String(),
		ExcludeTargets:             []string{"127.0.0.1"},
		RestrictLocalNetworkAccess: true,
	}

	err = protocolstate.Init(opts)
	require.NoError(t, err)

	// 3. Start headless proxy
	proxy, err := newHeadlessProxy(opts)
	require.NoError(t, err)
	defer func() {
		_ = proxy.Close()
	}()

	// 4. Test mapped IPv6 variations
	targets := []string{
		"[::ffff:127.0.0.1]:9999",
		"[0:0:0:0:0:ffff:127.0.0.1]:9999",
		"[::ffff:169.254.169.254]:80",
	}

	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxy.Addr())
			require.NoError(t, err)
			defer func() {
				_ = conn.Close()
			}()

			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			_, err = conn.Write([]byte(connectReq))
			require.NoError(t, err)

			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
		})
	}

	// Assert upstream proxy never received any connection for blocked mapped literals
	require.Zero(t, upstreamHits.Load(), "upstream proxy must not be reached for denied mapped literals")
}


