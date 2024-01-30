package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	mysqlplugin "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// MySQLClient is a client for MySQL database.
//
// Internally client uses go-sql-driver/mysql driver.
type MySQLClient struct{}

// Connect connects to MySQL database using given credentials.
//
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
//
// The connection is closed after the function returns.
func (c *MySQLClient) Connect(host string, port int, username, password string) (bool, error) {
	return connect(host, port, username, password, "INFORMATION_SCHEMA")
}

// IsMySQL checks if the given host is running MySQL database.
//
// If the host is running MySQL database, it returns true.
// If the host is not running MySQL database, it returns false.
func (c *MySQLClient) IsMySQL(host string, port int) (bool, error) {
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

// ConnectWithDB connects to MySQL database using given credentials and database name.
//
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
//
// The connection is closed after the function returns.
func (c *MySQLClient) ConnectWithDB(host string, port int, username, password, dbName string) (bool, error) {
	return connect(host, port, username, password, dbName)
}

// ConnectWithDSN connects to MySQL database using given DSN.
// we override mysql dialer with fastdialer so it respects network policy
func (c *MySQLClient) ConnectWithDSN(dsn string) (bool, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	_, err = db.Exec("select 1")
	if err != nil {
		return false, err
	}
	return true, nil
}

func connect(host string, port int, username, password, dbName string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}

	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	db, err := sql.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v)/%s?allowOldPasswords=1",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName))
	if err != nil {
		return false, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	_, err = db.Exec("select 1")
	if err != nil {
		return false, err
	}
	return true, nil
}

// ExecuteQuery connects to Mysql database using given credentials and database name.
// and executes a query on the db.
func (c *MySQLClient) ExecuteQuery(host string, port int, username, password, dbName, query string) (string, error) {

	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	db, err := sql.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v)/%s",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName))
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	rows, err := db.Query(query)
	if err != nil {
		return "", err
	}
	resp, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		return "", err
	}
	return string(resp), nil
}

func init() {
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
}
