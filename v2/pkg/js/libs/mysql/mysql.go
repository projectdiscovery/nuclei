package mysql

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	mysqlplugin "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
)

// Client is a client for MySQL database.
//
// Internally client uses go-sql-driver/mysql driver.
type Client struct{}

// Connect connects to MySQL database using given credentials.
//
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
//
// The connection is closed after the function returns.
func (c *Client) Connect(host string, port int, username, password string) (bool, error) {
	return connect(host, port, username, password, "INFORMATION_SCHEMA")
}

// IsMySQL checks if the given host is running MySQL database.
//
// If the host is running MySQL database, it returns true.
// If the host is not running MySQL database, it returns false.
func (c *Client) IsMySQL(host string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 5*time.Second)
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
func (c *Client) ConnectWithDB(host string, port int, username, password, dbName string) (bool, error) {
	return connect(host, port, username, password, dbName)
}

func connect(host string, port int, username, password, dbName string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	db, err := sql.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v)/%s",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName))
	if err != nil {
		return false, err
	}
	defer db.Close()

	_, err = db.Exec("select 1")
	if err != nil {
		return false, err
	}
	return true, nil
}
