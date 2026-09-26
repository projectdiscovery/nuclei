package postgres

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	postgres "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/postgresql"
	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils/pgwrap"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// PGClient is a client for Postgres database.
	// Internally client uses go-pg/pg driver.
	// @example
	// ```javascript
	// const postgres = require('nuclei/postgres');
	// const client = new postgres.PGClient;
	// ```
	PGClient struct{}

	// PostgresOptions defines the connection options for a Postgres database.
	PostgresOptions struct {
		Host     string
		Port     int
		Username string
		Password string
		DbName   string
		Timeout  int // Timeout is in seconds.
		SSLMode  string
	}
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

	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
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
//
// Deprecated: prefer ConnectWithOptions for new templates.
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

// ConnectWithOptions connects to Postgres using the supplied connection options.
func (c *PGClient) ConnectWithOptions(ctx context.Context, opts PostgresOptions) (bool, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	if _, err := postgresTLSConfig(opts.SSLMode, opts.Host); err != nil {
		return false, err
	}
	ok, err := c.IsPostgres(ctx, opts.Host, opts.Port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a postgres service")
	}
	executionId := ctx.Value("executionId").(string)
	return connectWithOptions(ctx, executionId, opts)
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

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	connStr := buildPostgresConnURL(username, password, target, dbName, executionId)
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

func buildPostgresConnURL(username, password, target, dbName, executionId string) string {
	return buildPostgresConnURLWithOptions(PostgresOptions{
		Username: username, Password: password, DbName: dbName,
	}, target, executionId)
}

func buildPostgresConnURLWithOptions(opts PostgresOptions, target, executionId string) string {
	values := url.Values{}
	sslMode := opts.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	values.Set("sslmode", sslMode)
	values.Set("executionId", executionId)

	return fmt.Sprintf("postgres://%s@%s/%s?%s",
		url.UserPassword(opts.Username, opts.Password).String(),
		target,
		url.PathEscape(opts.DbName),
		values.Encode(),
	)
}

// ConnectWithDB connects to Postgres database using given credentials and database name.
//
// Deprecated: prefer ConnectWithOptions for new templates.
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
	return connectWithOptions(ctx, executionId, PostgresOptions{
		Host: host, Port: port, Username: username, Password: password, DbName: dbName,
	})
}

func connectWithOptions(ctx context.Context, executionId string, opts PostgresOptions) (bool, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}

	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}

	target := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	tlsConfig, err := postgresTLSConfig(opts.SSLMode, opts.Host)
	if err != nil {
		return false, err
	}

	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	db := pg.Connect(&pg.Options{
		Addr:         target,
		User:         opts.Username,
		Password:     opts.Password,
		Database:     opts.DbName,
		TLSConfig:    tlsConfig,
		DialTimeout:  postgresTimeout(opts.Timeout),
		ReadTimeout:  postgresTimeout(opts.Timeout),
		WriteTimeout: postgresTimeout(opts.Timeout),
		Dialer: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Fastdialer.Dial(dialCtx, network, addr)
		},
		IdleCheckFrequency: -1,
	}).WithTimeout(postgresTimeout(opts.Timeout))

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

func postgresTimeout(timeout int) time.Duration {
	if timeout > 0 {
		return time.Duration(timeout) * time.Second
	}
	return 10 * time.Second
}

func postgresTLSConfig(sslMode, host string) (*tls.Config, error) {
	switch sslMode {
	case "", "disable":
		return nil, nil
	case "allow", "prefer":
		// go-pg cannot implement libpq's ordered plaintext/TLS fallback.
		return nil, fmt.Errorf("postgres sslmode %q is unsupported: TLS fallback is unavailable", sslMode)
	case "require", "verify-ca", "verify-full":
		// Always verify both the certificate chain and hostname. This intentionally
		// hardens require and verify-ca because the options API has no safe way to
		// configure a custom CA-only verifier without disabling the standard check.
		return &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported postgres sslmode %q", sslMode)
	}
}
