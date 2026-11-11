package ssh_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	sshlib "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/ssh"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type silentSSHPeer struct {
	listener net.Listener
	accepted chan net.Conn
	closed   chan struct{}
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newSilentSSHPeer(t *testing.T) *silentSSHPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	peer := &silentSSHPeer{
		listener: listener,
		accepted: make(chan net.Conn, 1),
		closed:   make(chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(peer.done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		peer.accepted <- conn

		// Read the client banner without replying; EOF proves the client closed TCP.
		readDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			close(readDone)
		}()
		select {
		case <-readDone:
			close(peer.closed)
		case <-peer.stop:
			_ = conn.Close()
			<-readDone
		}
	}()
	t.Cleanup(func() {
		peer.close()
		select {
		case <-peer.done:
		case <-time.After(3 * time.Second):
			t.Error("local peer cleanup timed out")
		}
	})

	return peer
}

func (p *silentSSHPeer) close() {
	p.once.Do(func() {
		close(p.stop)
		_ = p.listener.Close()
	})
}

func (p *silentSSHPeer) port() int { return p.listener.Addr().(*net.TCPAddr).Port }

func (p *silentSSHPeer) waitAccepted(t *testing.T) net.Conn {
	t.Helper()
	select {
	case conn := <-p.accepted:
		return conn
	case <-time.After(5 * time.Second):
		t.Fatal("SSH connection never reached the local peer")
	}
	return nil
}

func TestSSHInfoCancellation(t *testing.T) {
	for _, cancelCall := range []bool{false, true} {
		name := "peer-close-control"
		if cancelCall {
			name = "cancel-in-flight"
		}
		t.Run(name, func(t *testing.T) {
			peer := newSilentSSHPeer(t)
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), "executionId", t.Name()))
			defer cancel()
			done := make(chan error, 1)
			go func() {
				client := &sshlib.SSHClient{}
				_, err := client.ConnectSSHInfoMode(ctx, "127.0.0.1", peer.port())
				done <- err
			}()
			peer.waitAccepted(t)
			begin := time.Now()
			if cancelCall {
				cancel()
			} else {
				peer.close()
			}

			returned := false
			select {
			case err := <-done:
				returned = true
				t.Logf("call returned after %s: %v", time.Since(begin), err)
				if err == nil {
					t.Error("silent peer unexpectedly completed SSH handshake")
				}
			case <-time.After(time.Second):
				t.Errorf("SSH call still running 1s after trigger (cancel=%v)", cancelCall)
			}

			if cancelCall {
				select {
				case <-peer.closed:
					t.Log("client closed TCP after cancellation")
				case <-time.After(500 * time.Millisecond):
					t.Error("TCP connection remains open after cancellation")
				}
			}

			// Always stop the peer and wait for the call, including on regression failures.
			peer.close()
			if !returned {
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("SSH call did not stop after peer cleanup")
				}
			}
		})
	}
}

func TestJSDeadlineClosesSSHConnection(t *testing.T) {
	oldPooling := compiler.PoolingJsVmConcurrency
	compiler.PoolingJsVmConcurrency = 1
	defer func() { compiler.PoolingJsVmConcurrency = oldPooling }()

	peer := newSilentSSHPeer(t)
	done := make(chan error, 1)
	source := fmt.Sprintf(`const ssh = require('nuclei/ssh'); const c = new ssh.SSHClient(); Export(c.ConnectSSHInfoMode('127.0.0.1', %d));`, peer.port())
	begin := time.Now()
	go func() {
		_, err := executeSSHScript(t.Context(), source, 250*time.Millisecond)
		done <- err
	}()
	peer.waitAccepted(t)

	select {
	case err := <-done:
		t.Logf("JS call returned after %s: %v", time.Since(begin), err)
		if err == nil {
			t.Error("silent peer unexpectedly completed JS SSH check")
		}
	case <-time.After(4 * time.Second):
		peer.close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("JS call did not stop after peer cleanup")
		}
		t.Fatal("JS call did not return after execution deadline")
	}

	select {
	case <-peer.closed:
		t.Log("JS deadline closed the underlying TCP connection")
	case <-time.After(500 * time.Millisecond):
		t.Error("JS returned on timeout, but underlying SSH TCP connection is still open")
	}
	peer.close()
	// Wait for the peer cleanup before checking that the VM pool recovers.
	select {
	case <-peer.done:
	case <-time.After(3 * time.Second):
		t.Fatal("peer cleanup did not finish")
	}

	// A subsequent execution must be able to acquire the single pool slot.
	if _, err := executeSSHScript(t.Context(), `Export(true);`, 3*time.Second); err != nil {
		t.Errorf("JS pool did not recover after peer cleanup: %v", err)
	}
}

func executeSSHScript(ctx context.Context, source string, budget time.Duration) (compiler.ExecuteResult, error) {
	program, err := compiler.SourceAutoMode(source, false)
	if err != nil {
		return nil, err
	}
	return compiler.New().ExecuteWithOptions(ctx, program, nil, &compiler.ExecuteOptions{Source: &source, TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: budget}})
}

func TestSSHInfoAlreadyCanceled(t *testing.T) {
	peer := newSilentSSHPeer(t)
	ctx, cancel := context.WithCancel(executionContext(t))
	cancel()
	_, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, "127.0.0.1", peer.port())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	select {
	case <-peer.accepted:
		t.Fatal("canceled call opened TCP")
	default:
	}
}

func TestSSHInfoSuccessAndCache(t *testing.T) {
	host, port := startServer(t)
	ctx := executionContext(t)
	first, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first.ServerID == nil || first.ServerID.Raw == "" {
		t.Fatalf("missing SSH server information: %+v", first)
	}
	second, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, host, port)
	if err != nil || first != second {
		t.Fatalf("cached result = %p, %v; want %p, nil", second, err, first)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := new(sshlib.SSHClient).ConnectSSHInfoMode(canceled, host, port); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached canceled call = %v", err)
	}
}

func TestSSHInfoConcurrentCancellation(t *testing.T) {
	peer := newSilentSSHPeer(t)
	ctx, cancel := context.WithCancel(executionContext(t))
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, "127.0.0.1", peer.port())
		first <- err
	}()
	peer.waitAccepted(t)
	// The second connection is accepted directly, so both calls are certainly in flight.
	second := make(chan error, 1)
	go func() {
		_, err := new(sshlib.SSHClient).ConnectSSHInfoMode(executionContext(t), "127.0.0.1", peer.port())
		second <- err
	}()
	if err := peer.listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := peer.listener.Accept()
	if err != nil {
		peer.close()
		t.Fatal("second caller did not get an independent connection:", err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller did not return")
	}
	select {
	case err := <-second:
		t.Fatalf("other caller returned on first cancellation: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-second:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("peer error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second caller did not stop")
	}
}

func TestSSHInfoRetriesAfterError(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("cancel=", cancelFirst), func(t *testing.T) {
			peer := newSilentSSHPeer(t)
			ctx := executionContext(t)
			firstCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := new(sshlib.SSHClient).ConnectSSHInfoMode(firstCtx, "127.0.0.1", peer.port())
				done <- err
			}()
			conn := peer.waitAccepted(t)
			if cancelFirst {
				cancel()
			} else {
				conn.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("first handshake unexpectedly succeeded")
				}
				if cancelFirst && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
				if !cancelFirst && errors.Is(err, context.Canceled) {
					t.Fatalf("ordinary peer error became cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("first call did not return")
			}
			// Reuse the same address and execution ID, forwarding the next connection
			// to a real SSH server. Neither ordinary errors nor cancellation may poison the cache.
			host, port := startServer(t)
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				inbound, err := peer.listener.Accept()
				if err != nil {
					return
				}
				defer inbound.Close()
				outbound, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				if err != nil {
					return
				}
				defer outbound.Close()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(outbound, inbound); outbound.Close(); close(copied) }()
				_, _ = io.Copy(inbound, outbound)
				inbound.Close()
				<-copied
			}()
			retryCtx, retryCancel := context.WithTimeout(ctx, time.Second)
			defer retryCancel()
			result, err := new(sshlib.SSHClient).ConnectSSHInfoMode(retryCtx, "127.0.0.1", peer.port())
			if err != nil || result == nil || result.ServerID == nil {
				t.Fatalf("retry = %+v, %v", result, err)
			}
			select {
			case <-proxyDone:
			case <-time.After(time.Second):
				t.Fatal("successful info call left TCP open")
			}
			cached, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, "127.0.0.1", peer.port())
			if err != nil || cached != result {
				t.Fatalf("cached retry = %p, %v; want %p, nil", cached, err, result)
			}
		})
	}
}

func TestSSHInfoDeadlineClosesConnection(t *testing.T) {
	peer := newSilentSSHPeer(t)
	ctx, cancel := context.WithTimeout(executionContext(t), 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := new(sshlib.SSHClient).ConnectSSHInfoMode(ctx, "127.0.0.1", peer.port())
		done <- err
	}()
	peer.waitAccepted(t)
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not stop the SSH handshake")
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("deadline left TCP connection open")
	}
}
