package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	mysqlplugin "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
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
func (c *MySQLClient) IsMySQL(host string, port int) (bool, error) {
	// todo: why this is exposed? Service fingerprint should be automatic
	return memoizedisMySQL(host, port)
}

// @memo
func isMySQL(host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	if service == nil {
		return false, nil
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
func (c *MySQLClient) Connect(host string, port int, username, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(host, port)
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
	return connectWithDSN(dsn)
}

type (
	// MySQLInfo contains information about MySQL server.
	// this is returned when fingerprint is successful
	MySQLInfo struct {
		Host      string               `json:"host,omitempty"`
		IP        string               `json:"ip"`
		Port      int                  `json:"port"`
		Protocol  string               `json:"protocol"`
		TLS       bool                 `json:"tls"`
		Transport string               `json:"transport"`
		Version   string               `json:"version,omitempty"`
		Debug     plugins.ServiceMySQL `json:"debug,omitempty"`
		Raw       string               `json:"metadata"`
	}
)

// returns MySQLInfo when fingerpint is successful
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const info = mysql.FingerprintMySQL('acme.com', 3306);
// log(to_json(info));
// ```
func (c *MySQLClient) FingerprintMySQL(host string, port int) (MySQLInfo, error) {
	return memoizedfingerprintMySQL(host, port)
}

// @memo
func fingerprintMySQL(host string, port int) (MySQLInfo, error) {
	info := MySQLInfo{}
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return info, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return info, err
	}
	defer conn.Close()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return info, err
	}
	if service == nil {
		return info, fmt.Errorf("something went wrong got null output")
	}
	// fill all fields
	info.Host = service.Host
	info.IP = service.IP
	info.Port = service.Port
	info.Protocol = service.Protocol
	info.TLS = service.TLS
	info.Transport = service.Transport
	info.Version = service.Version
	info.Debug = service.Metadata().(plugins.ServiceMySQL)
	bin, _ := service.Raw.MarshalJSON()
	info.Raw = string(bin)
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
func (c *MySQLClient) ConnectWithDSN(dsn string) (bool, error) {
	return memoizedconnectWithDSN(dsn)
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
func (c *MySQLClient) ExecuteQueryWithOpts(opts MySQLOptions, query string) (*utils.SQLResult, error) {
	if !protocolstate.IsHostAllowed(opts.Host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}

	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(opts.Host, opts.Port)
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

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	rows, err := db.Query(query)
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
func (c *MySQLClient) ExecuteQuery(host string, port int, username, password, query string) (*utils.SQLResult, error) {
	// executing queries implies the remote mysql service
	ok, err := c.IsMySQL(host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a mysql service")
	}

	return c.ExecuteQueryWithOpts(MySQLOptions{
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
func (c *MySQLClient) ExecuteQueryOnDB(host string, port int, username, password, dbname, query string) (*utils.SQLResult, error) {
	return c.ExecuteQueryWithOpts(MySQLOptions{
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
