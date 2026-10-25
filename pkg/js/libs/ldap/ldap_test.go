package ldap

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestNewClientDeniesRestrictedLocalTCPBeforeDial(t *testing.T) {
	_, err := newLDAPClientForTest(t, &types.Options{
		RestrictLocalNetworkAccess: true,
	}, "ldap://127.0.0.1")

	requireNetworkPolicyError(t, err, "127.0.0.1")
	requireRejectedBeforeDial(t, err)
}

func TestNewClientDeniesLDAPIAsLocalNetworkAccess(t *testing.T) {
	_, err := newLDAPClientForTest(t, &types.Options{
		RestrictLocalNetworkAccess: true,
	}, "ldapi:///var/run/slapd/ldapi")

	requireNetworkPolicyError(t, err, "127.0.0.1")
	requireRejectedBeforeDial(t, err)
}

func requireRejectedBeforeDial(t *testing.T, err error) {
	t.Helper()

	if strings.Contains(err.Error(), "failed to connect to ldap server") {
		t.Fatalf("ldap target should be rejected by policy before dialing, got %q", err)
	}
}

func TestNewClientAllowsTCPWhenNetworkPolicyAllows(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			return
		}
		accepted <- nil
	}()

	client, err := newLDAPClientForTest(t, &types.Options{}, "ldap://"+listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.conn.Close()
	})

	select {
	case conn := <-accepted:
		if conn == nil {
			t.Fatal("listener closed before accepting ldap connection")
		}
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("ldap constructor did not connect to allowed listener")
	}
}

// A server that accepts and never answers used to keep Authenticate, and the runtime
// abandoned around it, blocked for the life of the process.
func TestAuthenticateReturnsWhenTheContextIsDone(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	go func() {
		var held []net.Conn
		for {
			conn, err := listener.Accept()
			if err != nil {
				for _, c := range held {
					_ = c.Close()
				}
				return
			}
			held = append(held, conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := newLDAPClientWithContextForTest(t, ctx, &types.Options{}, "ldap://"+listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			_ = recover() // the failed bind is thrown to the runtime
		}()
		client.Authenticate("user", "")
	}()

	select {
	case <-done:
		t.Fatal("Authenticate returned before the server answered or the context was done")
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate still blocked after the context was done")
	}
}

func newLDAPClientForTest(t *testing.T, options *types.Options, ldapURL string) (*Client, error) {
	t.Helper()
	return newLDAPClientWithContextForTest(t, context.Background(), options, ldapURL)
}

func newLDAPClientWithContextForTest(t *testing.T, ctx context.Context, options *types.Options, ldapURL string) (*Client, error) {
	t.Helper()

	executionID := "ldap-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	options.ExecutionId = executionID
	if err := protocolstate.Init(options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		protocolstate.Close(executionID)
	})

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", ctx)

	obj, err := runtime.New(runtime.ToValue(NewClient), runtime.ToValue(ldapURL), runtime.ToValue("corp.internal"))
	if err != nil {
		return nil, err
	}

	client, ok := obj.Export().(*Client)
	if !ok {
		t.Fatalf("expected *Client export, got %T", obj.Export())
	}
	return client, nil
}

func requireNetworkPolicyError(t *testing.T, err error, target string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected network-policy denial, got nil")
	}
	if !strings.Contains(err.Error(), "network policy") || !strings.Contains(err.Error(), target) {
		t.Fatalf("expected network-policy denial for %q, got %q", target, err)
	}
}
