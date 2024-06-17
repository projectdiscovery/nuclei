package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-pg/pg"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	postgres "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/postgresql"
	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils/pgwrap"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/utils/pgwrap"
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
)

// IsPostgres checks if the given host and port are running Postgres database.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// @example
// ```javascript
// const postgres = require('nuclei/postgres');
// const isPostgres = postgres.IsPostgres('acme.com', 5432);
// ```
func (c *PGClient) IsPostgres(host string, port int) (bool, error) {
	// todo: why this is exposed? Service fingerprint should be automatic
	return memoizedisPostgres(host, port)
}

// @memo
func isPostgres(host string, port int) (bool, error) {
	timeout := 10 * time.Second

	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, err
	}
	defer conn.Close()

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
func (c *PGClient) Connect(host string, port int, username, password string) (bool, error) {
	ok, err := c.IsPostgres(host, port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a postgres service")
	}
	return memoizedconnect(host, port, username, password, "postgres")
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
func (c *PGClient) ExecuteQuery(host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	ok, err := c.IsPostgres(host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a postgres service")
	}

	return memoizedexecuteQuery(host, port, username, password, dbName, query)
}

// @memo
func executeQuery(host string, port int, username string, password string, dbName string, query string) (*utils.SQLResult, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", username, password, target, dbName)
	db, err := sql.Open(pgwrap.PGWrapDriver, connStr)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	resp, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		return nil, err
	}
	return resp, nil
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
func (c *PGClient) ConnectWithDB(host string, port int, username, password, dbName string) (bool, error) {
	ok, err := c.IsPostgres(host, port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a postgres service")
	}

	return memoizedconnect(host, port, username, password, dbName)
}

// @memo
func connect(host string, port int, username string, password string, dbName string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}

	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := pg.Connect(&pg.Options{
		Addr:     target,
		User:     username,
		Password: password,
		Database: dbName,
		Dialer: func(network, addr string) (net.Conn, error) {
			return protocolstate.Dialer.Dial(context.Background(), network, addr)
		},
		IdleCheckFrequency: -1,
	}).WithContext(ctx).WithTimeout(10 * time.Second)
	defer db.Close()

	_, err := db.Exec("select 1")
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
