package mysql

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// MySQLClient is a client for MySQL database.
	// Internally client uses go-sql-driver/mysql driver.
	// @example
	// ```javascript
	// const mysql = require('nuclei/mysql');
	// const client = new mysql.MySQLClient;
	// ```
	MySQLClient struct{}
)

// IsMySQL checks if the given host is running MySQL database.
// If the host is running MySQL database, it returns true.
// If the host is not running MySQL database, it returns false.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const isMySQL = mysql.IsMySQL('acme.com', 3306);
// ```
func (c *MySQLClient) IsMySQL(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// todo: why this is exposed? Service fingerprint should be automatic
	return memoizedisMySQL(ctx, executionId, host, port)
}

// @memo
func isMySQL(ctx context.Context, executionId string, host string, port int) (bool, error) {
	// Reuse the memoized fingerprint probe so IsMySQL + FingerprintMySQL share one dial.
	_, err := memoizedfingerprintMySQL(ctx, executionId, host, port)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Connect connects to MySQL database using given credentials.
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const client = new mysql.MySQLClient;
// const connected = client.Connect('acme.com', 3306, 'username', 'password');
// ```
func (c *MySQLClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(ctx, host, port)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("not a mysql service")
	}

	dsn, err := BuildDSN(MySQLOptions{
		Host:     host,
		Port:     port,
		DbName:   "INFORMATION_SCHEMA",
		Protocol: "tcp",
		Username: username,
		Password: password,
	})
	if err != nil {
		return false, err
	}
	return memoizedconnectWithDSN(ctx, executionId, dsn)
}

type (
	// MySQLInfo contains information about MySQL server.
	// this is returned when fingerprint is successful
	MySQLInfo struct {
		Host            string        `json:"host,omitempty"`
		IP              string        `json:"ip"`
		Port            int           `json:"port"`
		Protocol        string        `json:"protocol"`
		TLS             bool          `json:"tls"`
		Transport       string        `json:"transport"`
		Version         string        `json:"version,omitempty"`
		ProtocolVersion int           `json:"protocolVersion,omitempty"`
		ThreadID        uint32        `json:"threadId,omitempty"`
		CapabilityFlags uint32        `json:"capabilityFlags,omitempty"`
		Capabilities    []string      `json:"capabilities,omitempty"`
		CharacterSet    uint8         `json:"characterSet,omitempty"`
		StatusFlags     uint16        `json:"statusFlags,omitempty"`
		Status          []string      `json:"status,omitempty"`
		Salt            string        `json:"salt,omitempty"`
		AuthPluginName  string        `json:"authPluginName,omitempty"`
		Debug           HandshakeInfo `json:"debug,omitempty"`
		Raw             string        `json:"metadata"`
	}
)

// returns MySQLInfo when fingerprint is successful
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const info = mysql.FingerprintMySQL('acme.com', 3306);
// log(to_json(info));
// ```
func (c *MySQLClient) FingerprintMySQL(ctx context.Context, host string, port int) (MySQLInfo, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedfingerprintMySQL(ctx, executionId, host, port)
}

// @memo
func fingerprintMySQL(ctx context.Context, executionId string, host string, port int) (MySQLInfo, error) {
	info := MySQLInfo{}
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return info, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return MySQLInfo{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return info, err
	}
	defer func() {
		_ = conn.Close()
	}()

	handshake, err := fingerprintConn(conn, mysqlFingerprintTimeout)
	if err != nil {
		return info, err
	}

	info.Host = host
	info.Port = port
	info.Protocol = "mysql"
	info.Transport = "tcp"
	info.TLS = false
	if hostIP := net.ParseIP(host); hostIP != nil {
		info.IP = hostIP.String()
	} else if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok && remote.IP != nil {
		info.IP = remote.IP.String()
	}
	info.Version = handshake.Version
	info.ProtocolVersion = handshake.ProtocolVersion
	info.ThreadID = handshake.ThreadID
	info.CapabilityFlags = handshake.CapabilityFlags
	info.Capabilities = handshake.Capabilities
	info.CharacterSet = handshake.CharacterSet
	info.StatusFlags = handshake.StatusFlags
	info.Status = handshake.Status
	info.Salt = handshake.Salt
	info.AuthPluginName = handshake.AuthPluginName
	info.Debug = handshake
	info.Raw = handshakeToJSON(handshake)
	return info, nil
}

// ConnectWithDSN connects to MySQL database using given DSN.
// we override mysql dialer with fastdialer so it respects network policy
// If connection is successful, it returns true.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const client = new mysql.MySQLClient;
// const connected = client.ConnectWithDSN('username:password@tcp(acme.com:3306)/');
// ```
func (c *MySQLClient) ConnectWithDSN(ctx context.Context, dsn string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnectWithDSN(ctx, executionId, dsn)
}

// ExecuteQueryWithOpts connects to Mysql database using given credentials
// and executes a query on the db.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const options = new mysql.MySQLOptions();
// options.Host = 'acme.com';
// options.Port = 3306;
// const result = mysql.ExecuteQueryWithOpts(options, 'SELECT * FROM users');
// log(to_json(result));
// ```
func (c *MySQLClient) ExecuteQueryWithOpts(ctx context.Context, opts MySQLOptions, query string) (*utils.SQLResult, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}

	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(ctx, opts.Host, opts.Port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a mysql service")
	}

	dsn, err := BuildDSN(opts)
	if err != nil {
		return nil, err
	}

	db, err := openDB(executionId, dsn)
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
		if len(data.Rows) > 0 {
			// allow partial results
			return data, nil
		}
		return nil, err
	}
	return data, nil
}

// ExecuteQuery connects to Mysql database using given credentials
// and executes a query on the db.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const result = mysql.ExecuteQuery('acme.com', 3306, 'username', 'password', 'SELECT * FROM users');
// log(to_json(result));
// ```
func (c *MySQLClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, query string) (*utils.SQLResult, error) {
	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a mysql service")
	}

	return c.ExecuteQueryWithOpts(ctx, MySQLOptions{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Username: username,
		Password: password,
	}, query)
}

// ExecuteQuery connects to Mysql database using given credentials
// and executes a query on the db.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const result = mysql.ExecuteQueryOnDB('acme.com', 3306, 'username', 'password', 'dbname', 'SELECT * FROM users');
// log(to_json(result));
// ```
func (c *MySQLClient) ExecuteQueryOnDB(ctx context.Context, host string, port int, username, password, dbname, query string) (*utils.SQLResult, error) {
	return c.ExecuteQueryWithOpts(ctx, MySQLOptions{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Username: username,
		Password: password,
		DbName:   dbname,
	}, query)
}

func init() {
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
}
