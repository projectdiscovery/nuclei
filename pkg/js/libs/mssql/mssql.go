package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mssql"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// Client is a client for MS SQL database.
	// Internally client uses microsoft/go-mssqldb driver.
	// @example
	// ```javascript
	// const mssql = require('nuclei/mssql');
	// const client = new mssql.MSSQLClient;
	// ```
	MSSQLClient struct{}
)

// Connect connects to MS SQL database using given credentials.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const client = new mssql.MSSQLClient;
// const connected = client.Connect('acme.com', 1433, 'username', 'password');
// ```
func (c *MSSQLClient) Connect(host string, port int, username, password string) (bool, error) {
	return memoizedconnect(host, port, username, password, "master")
}

// ConnectWithDB connects to MS SQL database using given credentials and database name.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const client = new mssql.MSSQLClient;
// const connected = client.ConnectWithDB('acme.com', 1433, 'username', 'password', 'master');
// ```
func (c *MSSQLClient) ConnectWithDB(host string, port int, username, password, dbName string) (bool, error) {
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

	connString := fmt.Sprintf("sqlserver://%s:%s@%s?database=%s&connection+timeout=30",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName)

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return false, err
	}
	defer db.Close()

	_, err = db.Exec("select 1")
	if err != nil {
		switch {
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

// IsMssql checks if the given host is running MS SQL database.
// If the host is running MS SQL database, it returns true.
// If the host is not running MS SQL database, it returns false.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const isMssql = mssql.IsMssql('acme.com', 1433);
// ```
func (c *MSSQLClient) IsMssql(host string, port int) (bool, error) {
	return memoizedisMssql(host, port)
}

// @memo
func isMssql(host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	data, check, err := mssql.DetectMSSQL(conn, 5*time.Second)
	if check && err != nil {
		return false, nil
	} else if !check && err != nil {
		return false, err
	}
	if data.Version != "" {
		return true, nil
	}
	return false, nil
}
