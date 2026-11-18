package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	postgres "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/postgresql"
	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils/pgwrap"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// PGClient is a client for Postgres database.
	// Internally client uses lib/pq driver.
	// @example
	// ```javascript
	// const postgres = require('nuclei/postgres');
	// const client = new postgres.PGClient;
	// ```
	PGClient struct{}
)

// IsPostgres checks if the given host and port are running Postgres database.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// @example
// ```javascript
// const postgres = require('nuclei/postgres');
// const isPostgres = postgres.IsPostgres('acme.com', 5432);
// ```
func (c *PGClient) IsPostgres(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// todo: why this is exposed? Service fingerprint should be automatic
	return memoizedisPostgres(ctx, executionId, host, port)
}

// @memo
func isPostgres(ctx context.Context, executionId string, host string, port int) (bool, error) {
	timeout := 10 * time.Second

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	plugin := &postgres.POSTGRESPlugin{}
	service, err := plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	if service == nil {
		return false, nil
	}
	return true, nil
}

// Connect connects to Postgres database using given credentials.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const postgres = require('nuclei/postgres');
// const client = new postgres.PGClient;
// const connected = client.Connect('acme.com', 5432, 'username', 'password');
// ```
func (c *PGClient) Connect(ctx context.Context, host string, port int, username string, password string) (bool, error) {
	ok, err := c.IsPostgres(ctx, host, port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a postgres service")
	}
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(ctx, executionId, host, port, username, password, "postgres")
}

// ExecuteQuery connects to Postgres database using given credentials and database name.
// and executes a query on the db.
// If connection is successful, it returns the result of the query.
// @example
// ```javascript
// const postgres = require('nuclei/postgres');
// const client = new postgres.PGClient;
// const result = client.ExecuteQuery('acme.com', 5432, 'username', 'password', 'dbname', 'select * from users');
// log(to_json(result));
// ```
func (c *PGClient) ExecuteQuery(ctx context.Context, host string, port int, username string, password string, dbName string, query string) (*utils.SQLResult, error) {
	ok, err := c.IsPostgres(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a postgres service")
	}

	executionId := ctx.Value("executionId").(string)

	return memoizedexecuteQuery(ctx, executionId, host, port, username, password, dbName, query)
}

// @memo
func executeQuery(ctx context.Context, executionId string, host string, port int, username string, password string, dbName string, query string) (*utils.SQLResult, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	connStr := buildPostgresDSN(host, port, username, password, dbName)
	db, err := pgwrap.OpenDB(ctx, executionId, connStr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	resp, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// buildPostgresDSN returns a lib/pq key=value connection string. user, password, dbname, service and passfile
// are always set, also when empty: lib/pq fills unset values from the scanner's environment (PGUSER, PGPASSWORD,
// PGDATABASE), a service file (PGSERVICE) and ~/.pgpass (PGPASSFILE), which sends the operator's credentials to the target.
func buildPostgresDSN(host string, port int, username, password, dbName string) string {
	quote := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	params := []struct{ key, value string }{
		{"host", host},
		{"port", strconv.Itoa(port)},
		{"user", username},
		{"password", password},
		{"dbname", dbName},
		{"sslmode", "disable"},
		{"connect_timeout", "10"},
		{"service", ""},
		{"options", ""},
		{"application_name", ""},
		// a path below a file never exists, so no password file is read
		{"passfile", filepath.Join(os.DevNull, "pgpass")},
	}
	kvs := make([]string, 0, len(params))
	for _, param := range params {
		kvs = append(kvs, param.key+"='"+quote.Replace(param.value)+"'")
	}
	return strings.Join(kvs, " ")
}

// ConnectWithDB connects to Postgres database using given credentials and database name.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const postgres = require('nuclei/postgres');
// const client = new postgres.PGClient;
// const connected = client.ConnectWithDB('acme.com', 5432, 'username', 'password', 'dbname');
// ```
func (c *PGClient) ConnectWithDB(ctx context.Context, host string, port int, username string, password string, dbName string) (bool, error) {
	ok, err := c.IsPostgres(ctx, host, port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a postgres service")
	}

	executionId := ctx.Value("executionId").(string)

	return memoizedconnect(ctx, executionId, host, port, username, password, dbName)
}

// @memo
func connect(ctx context.Context, executionId string, host string, port int, username string, password string, dbName string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}

	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// lib/pq with every credential set, as go-pg replaces an empty user, password or database
	// with PGUSER, PGPASSWORD or PGDATABASE from the scanner's environment
	db, err := pgwrap.OpenDB(execCtx, executionId, buildPostgresDSN(host, port, username, password, dbName))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = db.Close()
	}()

	_, err = db.ExecContext(execCtx, "select 1")
	if err != nil {
		switch true {
		case strings.Contains(err.Error(), "connect: connection refused"):
			fallthrough
		case strings.Contains(err.Error(), "no pg_hba.conf entry for host"):
			fallthrough
		case strings.Contains(err.Error(), "network unreachable"):
			fallthrough
		case strings.Contains(err.Error(), "reset"):
			fallthrough
		case strings.Contains(err.Error(), "i/o timeout"):
			return false, err
		}
		return false, nil
	}
	return true, nil
}
