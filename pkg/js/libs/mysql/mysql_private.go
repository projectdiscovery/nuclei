package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// MySQLOptions defines the data source name (DSN) options required to connect to a MySQL database.
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
func BuildDSN(opts MySQLOptions) (string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return "", fmt.Errorf("invalid host or port")
	}
	if opts.Protocol == "" {
		opts.Protocol = "tcp"
	}
	// Switch to nucleitcp which handles SSRF and custom dialing
	if opts.Protocol == "tcp" {
		opts.Protocol = "nucleitcp"
	}
	if opts.DbName == "" {
		opts.DbName = "/"
	} else {
		if !strings.HasPrefix(opts.DbName, "/") {
			opts.DbName = "/" + opts.DbName
		}
	}
	target := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	var dsn strings.Builder
	// Escaping both username and password to prevent DSN parsing errors and security issues
	dsn.WriteString(fmt.Sprintf("%v:%v", url.QueryEscape(opts.Username), url.QueryEscape(opts.Password)))
	dsn.WriteString("@")
	dsn.WriteString(fmt.Sprintf("%v(%v)", opts.Protocol, target))
	dsn.WriteString(opts.DbName)
	if opts.RawQuery != "" {
		dsn.WriteString(opts.RawQuery)
	}
	return dsn.String(), nil
}

// @memo
func connectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	// ໝາຍເຫດ: SSRF Check ຖືກຍ້າຍໄປກວດຢູ່ຟັງຊັນ Connect ກ່ອນຈະສ້າງ DSN ແລ້ວ
	// ເພື່ອປ້ອງກັນການຮົ່ວໄຫຼຂອງຂໍ້ມູນ (Credential Leak) ໃນ error message.
	
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = db.Close()
	}()
	
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// Use the passed context for Ping to handle timeouts correctly
	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}
