package ssh_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	libssh "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/ssh"
	"github.com/zmap/zgrab2/lib/ssh"
)

const (
	testUser     = "user"
	testPassword = "secret"
)

var errAccessDenied = errors.New("access denied")

func TestCloseWithoutConnection(t *testing.T) {
	t.Parallel()

	host, port := startServer(t)

	tests := map[string]func(t *testing.T, client *libssh.SSHClient){
		"never connected": func(*testing.T, *libssh.SSHClient) {},
		"failed connect": func(t *testing.T, client *libssh.SSHClient) {
			t.Helper()

			_, err := client.Connect(executionContext(t), host, port, testUser, "wrong")
			if err == nil {
				t.Fatal("Connect() with a wrong password succeeded")
			}
		},
		"already closed": func(t *testing.T, client *libssh.SSHClient) {
			t.Helper()

			connect(t, client, host, port)
			closeClient(t, client)
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := new(libssh.SSHClient)
			setup(t, client)
			closeClient(t, client)

			_, err := client.Run("id")
			if err == nil || !strings.Contains(err.Error(), "no connection") {
				t.Errorf("Run() error = %v, want no connection", err)
			}
		})
	}
}

func TestCloseConnected(t *testing.T) {
	t.Parallel()

	host, port := startServer(t)
	client := new(libssh.SSHClient)
	connect(t, client, host, port)
	closeClient(t, client)
}

func connect(t *testing.T, client *libssh.SSHClient, host string, port int) {
	t.Helper()

	_, err := client.Connect(executionContext(t), host, port, testUser, testPassword)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
}

func closeClient(t *testing.T, client *libssh.SSHClient) {
	t.Helper()

	closed, err := client.Close()
	if err != nil || !closed {
		t.Fatalf("Close() = %v, %v; want true, nil", closed, err)
	}
}

func executionContext(t *testing.T) context.Context {
	t.Helper()

	return context.WithValue(t.Context(), "executionId", t.Name()) //nolint:staticcheck // Connect reads this string key.
}

// startServer serves SSH on a loopback port and accepts only
// testUser with testPassword. It rejects every channel.
func startServer(t *testing.T) (string, int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	config := new(ssh.ServerConfig)
	config.PasswordCallback = checkPassword
	config.AddHostKey(signer)

	listener, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go serve(conn, config)
		}
	}()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not TCP", listener.Addr())
	}

	return addr.IP.String(), addr.Port
}

func checkPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if conn.User() != testUser || string(password) != testPassword {
		return nil, errAccessDenied
	}

	return new(ssh.Permissions), nil
}

func serve(conn net.Conn, config *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()

	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		_ = ch.Reject(ssh.Prohibited, "test server")
	}
}
