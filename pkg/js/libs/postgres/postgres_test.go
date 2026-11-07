package postgres

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBuildPostgresDSNEscapesDBName(t *testing.T) {
	dbName := "testdb' sslrootcert='/etc/passwd' sslmode='verify-ca"
	cfg, err := pq.NewConfig(buildPostgresDSN("127.0.0.1", 5432, "postgres", "x", dbName))
	require.NoError(t, err)

	require.Equal(t, dbName, cfg.Database)
	require.Equal(t, pq.SSLModeDisable, cfg.SSLMode)
	require.Empty(t, cfg.SSLRootCert)
	require.Empty(t, cfg.Runtime)
}

func TestBuildPostgresDSNEscapesCredentials(t *testing.T) {
	username := `user:name@example.com' host='other`
	password := `pa:ss@word?x\' sslmode='require`
	cfg, err := pq.NewConfig(buildPostgresDSN("127.0.0.1", 5432, username, password, "postgres"))
	require.NoError(t, err)

	require.Equal(t, username, cfg.User)
	require.Equal(t, password, cfg.Password)
	require.Equal(t, "127.0.0.1", cfg.Host)
	require.Equal(t, uint16(5432), cfg.Port)
	require.Equal(t, "postgres", cfg.Database)
	require.Equal(t, pq.SSLModeDisable, cfg.SSLMode)
}

// setOperatorPostgresEnv sets every source lib/pq and go-pg read credentials from
func setOperatorPostgresEnv(t *testing.T) {
	home := t.TempDir()
	pgpass := filepath.Join(home, ".pgpass")
	require.NoError(t, os.WriteFile(pgpass, []byte("*:*:*:*:OPERATOR-PGPASS-SECRET\n"), 0600))
	serviceFile := filepath.Join(home, ".pg_service.conf")
	require.NoError(t, os.WriteFile(serviceFile, []byte("[operator]\npassword=OPERATOR-SERVICE-SECRET\n"), 0600))

	t.Setenv("HOME", home)
	t.Setenv("PGPASSFILE", pgpass)
	t.Setenv("PGSERVICEFILE", serviceFile)
	t.Setenv("PGSERVICE", "operator")
	t.Setenv("PGPASSWORD", "OPERATOR-ENV-PGPASSWORD")
	t.Setenv("PGUSER", "operator-user")
	t.Setenv("PGDATABASE", "operator-db")
	t.Setenv("PGOPTIONS", "-c search_path=operator")
	t.Setenv("PGAPPNAME", "operator-app")
}

func TestBuildPostgresDSNIgnoresOperatorEnvironment(t *testing.T) {
	setOperatorPostgresEnv(t)

	cfg, err := pq.NewConfig(buildPostgresDSN("127.0.0.1", 5432, "", "", ""))
	require.NoError(t, err)
	require.Empty(t, cfg.User)
	require.Empty(t, cfg.Password)
	require.Empty(t, cfg.Database)
	require.Empty(t, cfg.Service)
	require.Empty(t, cfg.Options)
	require.Empty(t, cfg.ApplicationName)
}

type startup struct {
	user, database, password string
}

// fakePostgres asks every client for a cleartext password, records it and rejects the login
func fakePostgres(t *testing.T) (int, <-chan startup) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	logins := make(chan startup, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				readMessage := func(typed bool) []byte {
					header := make([]byte, 4)
					if typed {
						header = make([]byte, 5)
					}
					if _, err := io.ReadFull(conn, header); err != nil {
						return nil
					}
					body := make([]byte, binary.BigEndian.Uint32(header[len(header)-4:])-4)
					if _, err := io.ReadFull(conn, body); err != nil {
						return nil
					}
					return body
				}
				params := readMessage(false)
				if len(params) < 4 {
					return
				}
				fields := strings.Split(string(params[4:]), "\x00")
				var login startup
				for i := 0; i+1 < len(fields); i += 2 {
					switch fields[i] {
					case "user":
						login.user = fields[i+1]
					case "database":
						login.database = fields[i+1]
					}
				}
				// AuthenticationCleartextPassword
				if _, err := conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}); err != nil {
					return
				}
				password := readMessage(true)
				login.password = strings.TrimSuffix(string(password), "\x00")
				logins <- login
				errorBody := "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
				header := []byte{'E', 0, 0, 0, 0}
				binary.BigEndian.PutUint32(header[1:], uint32(len(errorBody)+4))
				_, _ = conn.Write(append(header, errorBody...))
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, logins
}

func TestPostgresEmptyCredentialsAreNotFilledFromEnvironment(t *testing.T) {
	setOperatorPostgresEnv(t)

	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	port, logins := fakePostgres(t)
	ctx := context.Background()

	_, err := executeQuery(ctx, executionID, "127.0.0.1", port, "postgres", "", "postgres", "select 1")
	require.Error(t, err)
	require.Equal(t, startup{user: "postgres", database: "postgres"}, <-logins)

	connected, err := connect(ctx, executionID, "127.0.0.1", port, "postgres", "", "postgres")
	require.NoError(t, err)
	require.False(t, connected)
	require.Equal(t, startup{user: "postgres", database: "postgres"}, <-logins)

	_, _ = connect(ctx, executionID, "127.0.0.1", port, "", "", "")
	require.Equal(t, startup{}, <-logins)

	_, _ = executeQuery(ctx, executionID, "127.0.0.1", port, "admin", "secret", "db", "select 1")
	require.Equal(t, startup{user: "admin", database: "db", password: "secret"}, <-logins)

}
