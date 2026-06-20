package postgres

import (
	"net/url"
	"strings"
	"testing"

	"github.com/lib/pq"
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
