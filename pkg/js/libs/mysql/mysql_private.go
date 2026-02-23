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

type MySQLOptions struct {
	Host     string
	Port     int
	Protocol string
	Username string
	Password string
	DbName   string
	RawQuery string
	Timeout  int
}

func BuildDSN(opts MySQLOptions) (string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return "", fmt.Errorf("invalid host or port")
	}
	if opts.Protocol == "" {
		opts.Protocol = "tcp"
	}
	if opts.Protocol == "tcp" {
		opts.Protocol = "nucleitcp"
	}
	if opts.DbName == "" {
		opts.DbName = "/"
	} else if !strings.HasPrefix(opts.DbName, "/") {
		opts.DbName = "/" + opts.DbName
	}
	target := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	return fmt.Sprintf("%s:%s@%s(%s)%s%s", 
		url.QueryEscape(opts.Username), 
		url.QueryEscape(opts.Password), 
		opts.Protocol, target, opts.DbName, opts.RawQuery), nil
}

func connectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	// SSRF Safety: Verify host allowance before opening connection
	if start := strings.Index(dsn, "("); start != -1 {
		if end := strings.Index(dsn, ")"); end != -1 {
			target := dsn[start+1 : end]
			host, _, _ := net.SplitHostPort(target)
			if host == "" { host = target }
			if !protocolstate.IsHostAllowed(executionId, host) {
				return false, protocolstate.ErrHostDenied.Msgf(host)
			}
		}
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil { return false, err }
	defer db.Close()

	db.SetMaxOpenConns(1)
	return db.PingContext(ctx) == nil, nil
}
