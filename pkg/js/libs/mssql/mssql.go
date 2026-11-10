package mssql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	gomssql "github.com/microsoft/go-mssqldb"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// mssqlCustomDialer routes connection dialing through Nuclei's fastdialer.
// Implementing HostDialer ensures the driver delegates hostname resolution to the dialer
// rather than using the local OS net.LookupIP, keeping DNS resolution, scan proxies,
// and dial-time network policies strictly enforced.
type mssqlCustomDialer struct {
	executionId string
	host        string
}

var _ gomssql.HostDialer = (*mssqlCustomDialer)(nil)

func (d *mssqlCustomDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(d.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", d.executionId)
	}
	targetHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		targetHost = addr
	}
	if !protocolstate.IsHostAllowed(d.executionId, targetHost) {
		return nil, protocolstate.ErrHostDenied.Msgf(targetHost)
	}
	return dialers.Fastdialer.Dial(ctx, network, addr)
}

func (d *mssqlCustomDialer) HostName() string {
	return d.host
}

func openDB(executionId, target, username, password, dbName string) (*sql.DB, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	connString := mssqlConnString(target, username, password, dbName)
	connector, err := gomssql.NewConnector(connString)
	if err != nil {
		return nil, err
	}
	connector.Dialer = &mssqlCustomDialer{
		executionId: executionId,
		host:        host,
	}
	return sql.OpenDB(connector), nil
}

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
func (c *MSSQLClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(ctx, executionId, host, port, username, password, "master")
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
func (c *MSSQLClient) ConnectWithDB(ctx context.Context, host string, port int, username, password, dbName string) (bool, error) {
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

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	db, err := openDB(executionId, target, username, password, dbName)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = db.Close()
	}()

	_, err = db.ExecContext(ctx, "select 1")
	if err != nil {
		if isNetworkError(err) {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

// isNetworkError reports whether an error indicates a network, dialer,
// timeout, or policy failure as opposed to a server-side authentication rejection.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	for _, marker := range []string{
		"connection refused",
		"actively refused",
		"port closed",
		"unable to open tcp connection",
		"network unreachable",
		"connection reset",
		"i/o timeout",
		"connection timed out",
		"context canceled",
		"deadline exceeded",
		"dialers not initialized",
		"network policy",
		"host denied",
	} {
		if strings.Contains(errStr, marker) {
			return true
		}
	}
	return false
}

// IsMssql checks if the given host is running MS SQL database.
// If the host is running MS SQL database, it returns true.
// If the host is not running MS SQL database, it returns false.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const isMssql = mssql.IsMssql('acme.com', 1433);
// ```
func (c *MSSQLClient) IsMssql(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisMssql(ctx, executionId, host, port)
}

// @memo
func isMssql(ctx context.Context, executionId string, host string, port int) (bool, error) {
	// Reuse the memoized fingerprint probe so IsMssql + FingerprintMssql share one dial.
	_, err := memoizedfingerprintMssql(ctx, executionId, host, port)
	return isMssqlResult(err)
}

// isMssqlResult maps fingerprint probe errors to IsMssql's (ok, err) contract.
func isMssqlResult(err error) (bool, error) {
	if err != nil {
		// Unparsable / non-MSSQL TDS replies are a negative detection, not a probe failure.
		if errors.Is(err, errNotMssql) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ExecuteQuery connects to MS SQL database using given credentials and executes a query.
// It returns the results of the query or an error if something goes wrong.
// @example
// ```javascript
// const mssql = require('nuclei/mssql');
// const client = new mssql.MSSQLClient;
// const result = client.ExecuteQuery('acme.com', 1433, 'username', 'password', 'master', 'SELECT @@version');
// log(to_json(result));
// ```
func (c *MSSQLClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	executionId := ctx.Value("executionId").(string)
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	ok, err := c.IsMssql(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a mssql service")
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	db, err := openDB(executionId, target, username, password, dbName)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}

	data, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		if data != nil && len(data.Rows) > 0 {
			return data, nil
		}
		return nil, err
	}
	return data, nil
}

func mssqlConnString(target, username, password, dbName string) string {
	return fmt.Sprintf("sqlserver://%s:%s@%s?database=%s&connection+timeout=30",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		url.QueryEscape(dbName))
}
