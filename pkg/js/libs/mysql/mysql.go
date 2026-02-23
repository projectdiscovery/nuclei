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

type MySQLClient struct{}

// executionIdFromCtx extracts the executionId from the context.
// This is a helper function to avoid code duplication across public methods.
func executionIdFromCtx(ctx context.Context) (string, error) {
	executionId, ok := ctx.Value("executionId").(string)
	if !ok {
		return "", fmt.Errorf("missing executionId in context")
	}
	return executionId, nil
}

// IsMySQL checks if the given host and port is a MySQL service
func (c *MySQLClient) IsMySQL(ctx context.Context, host string, port int) (bool, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return false, err
	}
	return memoizedisMySQL(ctx, executionId, host, port)
}

// @memo
func isMySQL(ctx context.Context, executionId string, host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	return service != nil, nil
}

// Connect attempts to connect to a MySQL server
func (c *MySQLClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return false, err
	}

	// isMySQL already performs the SSRF check internally
	isMySQLService, err := c.IsMySQL(ctx, host, port)
	if err != nil || !isMySQLService {
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

type MySQLInfo struct {
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

// FingerprintMySQL attempts to fingerprint a MySQL service
func (c *MySQLClient) FingerprintMySQL(ctx context.Context, host string, port int) (MySQLInfo, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return MySQLInfo{}, err
	}
	return memoizedfingerprintMySQL(ctx, executionId, host, port)
}

// @memo
func fingerprintMySQL(ctx context.Context, executionId string, host string, port int) (MySQLInfo, error) {
	info := MySQLInfo{}
	if !protocolstate.IsHostAllowed(executionId, host) {
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
	defer func() { _ = conn.Close() }()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return info, err
	}
	if service == nil {
		return info, fmt.Errorf("fingerprint failed: no service detected")
	}

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

// ConnectWithDSN attempts to connect to a MySQL server using a DSN
func (c *MySQLClient) ConnectWithDSN(ctx context.Context, dsn string) (bool, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return false, err
	}
	return memoizedconnectWithDSN(ctx, executionId, dsn)
}

// ExecuteQueryWithOpts executes a query on a MySQL server with options
func (c *MySQLClient) ExecuteQueryWithOpts(ctx context.Context, opts MySQLOptions, query string) (*utils.SQLResult, error) {
	// SSRF and service check
	isMySQLService, err := c.IsMySQL(ctx, opts.Host, opts.Port)
	if err != nil || !isMySQLService {
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
	defer func() { _ = db.Close() }()

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

// ExecuteQuery executes a query on a MySQL server
func (c *MySQLClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, query string) (*utils.SQLResult, error) {
	return c.ExecuteQueryWithOpts(ctx, MySQLOptions{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Username: username,
		Password: password,
	}, query)
}

// ExecuteQueryOnDB executes a query on a specific database of a MySQL server
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
