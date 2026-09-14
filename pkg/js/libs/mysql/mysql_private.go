package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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
	fmt.Fprintf(&dsn, "%v:%v", url.QueryEscape(opts.Username), opts.Password)
	dsn.WriteString("@")
	fmt.Fprintf(&dsn, "%v(%v)", opts.Protocol, target)
	if opts.DbName != "" {
		dsn.WriteString(opts.DbName)
	}
	if opts.RawQuery != "" {
		dsn.WriteString(opts.RawQuery)
	}
	return dsn.String(), nil
}

// sandboxDSN enforces the local file access sandbox on a MySQL DSN. The
// driver's allowAllFiles option lets a malicious server read any local file
// off the host via LOAD DATA LOCAL INFILE, so it is only honored when -lfa is
// enabled, mirroring the fs.ReadFile restriction.
func sandboxDSN(dsn string, lfaAllowed bool) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	if cfg.AllowAllFiles && !lfaAllowed {
		cfg.AllowAllFiles = false
	}
	return cfg.FormatDSN(), nil
}

// openDB opens a sandboxed MySQL connection from dsn.
func openDB(executionId, dsn string) (*sql.DB, error) {
	dsn, err := sandboxDSN(dsn, protocolstate.IsLfaAllowed(&types.Options{ExecutionId: executionId}))
	if err != nil {
		return nil, err
	}
	return sql.Open("mysql", dsn)
}

// @memo
func connectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	db, err := openDB(executionId, dsn)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = db.Close()
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	pingCtx := context.WithValue(ctx, "executionId", executionId) // nolint: staticcheck
	err = db.PingContext(pingCtx)
	if err != nil {
		return false, err
	}
	return true, nil
}
