package mysql

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type (
	// MySQLOptions defines the data source name (DSN) options required to connect to a MySQL database.
	// along with other options like Timeout etc
	// @example
	// ```javascript
	// const mysql = require('nuclei/mysql');
	// const options = new mysql.MySQLOptions();
	// options.Host = 'acme.com';
	// options.Port = 3306;
	// ```
	MySQLOptions struct {
		Host     string // Host is the host name or IP address of the MySQL server.
		Port     int    // Port is the port number on which the MySQL server is listening.
		Protocol string // Protocol is the protocol used to connect to the MySQL server (ex: "tcp").
		Username string // Username is the user name used to authenticate with the MySQL server.
		Password string // Password is the password used to authenticate with the MySQL server.
		DbName   string // DbName is the name of the database to connect to on the MySQL server.
		RawQuery string // QueryStr is the query string to append to the DSN (ex: "?tls=skip-verify").
		Timeout  int    // Timeout is the timeout in seconds for the connection to the MySQL server.
	}
)

// BuildDSN builds a MySQL data source name (DSN) from the given options.
// @example
// ```javascript
// const mysql = require('nuclei/mysql');
// const options = new mysql.MySQLOptions();
// options.Host = 'acme.com';
// options.Port = 3306;
// const dsn = mysql.BuildDSN(options);
// ```
func BuildDSN(opts MySQLOptions) (string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return "", fmt.Errorf("invalid host or port")
	}
	if opts.Protocol == "" {
		opts.Protocol = "tcp"
	}
	// We're going to use a custom dialer when creating MySQL connections, so if we've been
	// given "tcp" as the protocol, then quietly switch it to "nucleitcp", which we have
	// already registered.
	if opts.Protocol == "tcp" {
		opts.Protocol = "nucleitcp"
	}
	if opts.DbName == "" {
		opts.DbName = "/"
	} else {
		opts.DbName = "/" + opts.DbName
	}
	target := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	var dsn strings.Builder
	dsn.WriteString(fmt.Sprintf("%v:%v", url.QueryEscape(opts.Username), opts.Password))
	dsn.WriteString("@")
	dsn.WriteString(fmt.Sprintf("%v(%v)", opts.Protocol, target))
	if opts.DbName != "" {
		dsn.WriteString(opts.DbName)
	}
	if opts.RawQuery != "" {
		dsn.WriteString(opts.RawQuery)
	}
	return dsn.String(), nil
}

// @memo
func connectWithDSN(dsn string) (bool, error) {
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
