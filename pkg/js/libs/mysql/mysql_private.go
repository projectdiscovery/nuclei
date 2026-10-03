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

// sandboxDSN enforces local file and network policy on a MySQL DSN.
// allowAllFiles is only honored when -lfa is enabled. Raw tcp DSNs are
// rewritten to nucleitcp so the driver uses the fastdialer registered in
// protocolstate. Unix sockets are treated as loopback for -lna.
func sandboxDSN(executionId, dsn string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	opts := &types.Options{ExecutionId: executionId}
	if cfg.AllowAllFiles && !protocolstate.IsLfaAllowed(opts) {
		cfg.AllowAllFiles = false
	}

	netName := cfg.Net
	if netName == "" {
		netName = "tcp"
	}
	switch netName {
	case "unix":
		// IP-based policy never sees a socket path; gate on loopback like ldapi.
		const unixPolicyHost = "127.0.0.1"
		if !protocolstate.IsHostAllowed(executionId, unixPolicyHost) {
			return "", protocolstate.ErrHostDenied.Msgf(unixPolicyHost)
		}
	case "tcp":
		cfg.Net = "nucleitcp"
		fallthrough
	case "nucleitcp":
		host := dsnPolicyHost(cfg.Addr)
		if !protocolstate.IsHostAllowed(executionId, host) {
			return "", protocolstate.ErrHostDenied.Msgf(host)
		}
	default:
		host := dsnPolicyHost(cfg.Addr)
		if host != "" && !protocolstate.IsHostAllowed(executionId, host) {
			return "", protocolstate.ErrHostDenied.Msgf(host)
		}
	}
	return cfg.FormatDSN(), nil
}

func dsnPolicyHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}

// openDB opens a sandboxed MySQL connection from dsn.
func openDB(executionId, dsn string) (*sql.DB, error) {
	dsn, err := sandboxDSN(executionId, dsn)
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
