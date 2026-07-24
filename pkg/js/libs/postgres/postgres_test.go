package postgres

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestBuildPostgresConnectionURLDoesNotAllowDBNameQueryInjection(t *testing.T) {
	dbName := "testdb?sslrootcert=/etc/passwd&sslmode=verify-ca&junk="
	connStr := buildPostgresConnURL("postgres", "x", "127.0.0.1:5432", dbName, "exec-1")

	u, err := url.Parse(connStr)
	if err != nil {
		t.Fatalf("parse connection URL: %v", err)
	}

	if got := strings.TrimPrefix(u.Path, "/"); got != dbName {
		t.Fatalf("database name = %q, want %q", got, dbName)
	}

	values := u.Query()
	if got := values.Get("sslmode"); got != "disable" {
		t.Fatalf("sslmode = %q, want disable", got)
	}
	if got := values.Get("executionId"); got != "exec-1" {
		t.Fatalf("executionId = %q, want exec-1", got)
	}
	deniedParams := []string{"sslrootcert", "sslcert", "sslkey", "service", "junk"}
	for _, denied := range deniedParams {
		if got := values.Get(denied); got != "" {
			t.Fatalf("%s was injected with value %q", denied, got)
		}
	}

	pqDSN, err := pq.ParseURL(connStr) //nolint:staticcheck // validates lib/pq URL parsing of the generated DSN.
	if err != nil {
		t.Fatalf("parse connection URL as lib/pq DSN: %v", err)
	}
	if !strings.Contains(pqDSN, "dbname='"+dbName+"'") {
		t.Fatalf("lib/pq DSN = %q, want dbName preserved as dbname", pqDSN)
	}
	for _, denied := range deniedParams {
		if strings.Contains(pqDSN, " "+denied+"=") {
			t.Fatalf("%s was injected into lib/pq DSN %q", denied, pqDSN)
		}
	}
}

func TestBuildPostgresConnectionURLEscapesCredentials(t *testing.T) {
	username := "user:name@example.com"
	password := "pa:ss@word?x"
	connStr := buildPostgresConnURL(username, password, "127.0.0.1:5432", "postgres", "exec-1")

	u, err := url.Parse(connStr)
	if err != nil {
		t.Fatalf("parse connection URL: %v", err)
	}

	if got := u.User.Username(); got != username {
		t.Fatalf("username = %q, want %q", got, username)
	}
	if got, _ := u.User.Password(); got != password {
		t.Fatalf("password = %q, want %q", got, password)
	}
	if got := u.Host; got != "127.0.0.1:5432" {
		t.Fatalf("host = %q, want 127.0.0.1:5432", got)
	}
	if got := strings.TrimPrefix(u.Path, "/"); got != "postgres" {
		t.Fatalf("database name = %q, want postgres", got)
	}
}

func TestBuildPostgresConnectionURLMapsOptions(t *testing.T) {
	connStr := buildPostgresConnURLWithOptions(PostgresOptions{
		Username: "user", Password: "password", DbName: "app", SSLMode: "require",
	}, "127.0.0.1:5432", "exec-1")

	u, err := url.Parse(connStr)
	if err != nil {
		t.Fatalf("parse connection URL: %v", err)
	}
	if got := u.Query().Get("sslmode"); got != "require" {
		t.Fatalf("sslmode = %q, want require", got)
	}
	if got := strings.TrimPrefix(u.Path, "/"); got != "app" {
		t.Fatalf("database name = %q, want app", got)
	}
}

func TestPostgresTimeout(t *testing.T) {
	if got := postgresTimeout(3); got.String() != "3s" {
		t.Fatalf("timeout = %s, want 3s", got)
	}
	if got := postgresTimeout(0); got.String() != "10s" {
		t.Fatalf("default timeout = %s, want 10s", got)
	}
}

func TestPostgresTLSConfigMapsSSLMode(t *testing.T) {
	tlsConfig, err := postgresTLSConfig("require")
	if err != nil {
		t.Fatalf("map require SSL mode: %v", err)
	}
	if tlsConfig == nil || !tlsConfig.InsecureSkipVerify {
		t.Fatal("require SSL mode should enable TLS without certificate verification")
	}

	tlsConfig, err = postgresTLSConfig("disable")
	if err != nil {
		t.Fatalf("map disable SSL mode: %v", err)
	}
	if tlsConfig != nil {
		t.Fatal("disable SSL mode should not configure TLS")
	}
	if _, err := postgresTLSConfig("invalid"); err == nil {
		t.Fatal("expected unsupported SSL mode error")
	}
}

func TestConnectWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	if err := protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) // nolint:staticcheck
	connected, err := (&PGClient{}).ConnectWithOptions(ctx, PostgresOptions{
		Host: "127.0.0.1", Port: 5432, SSLMode: "require",
	})
	if connected || err == nil || !strings.Contains(err.Error(), "network policy") {
		t.Fatalf("expected network-policy denial before dialing, got connected=%t err=%v", connected, err)
	}
}
