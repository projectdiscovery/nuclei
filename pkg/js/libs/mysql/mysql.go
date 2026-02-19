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
	MySQLClient struct{}
)

func (c *MySQLClient) IsMySQL(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປຫາ memoizedisMySQL
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

	// ແກ້ໄຂ: ປ່ຽນ context.TODO() ເປັນ ctx
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

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

func (c *MySQLClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

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
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedconnectWithDSN(ctx, executionId, dsn)
}

type (
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

func (c *MySQLClient) FingerprintMySQL(ctx context.Context, host string, port int) (MySQLInfo, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
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

	// ແກ້ໄຂ: ປ່ຽນ context.TODO() ເປັນ ctx
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return info, err
	}
	defer func() {
		_ = conn.Close()
	}()

	plugin := &mysqlplugin.MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return info, err
	}
	if service == nil {
		return info, fmt.Errorf("something went wrong got null output")
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

func (c *MySQLClient) ConnectWithDSN(ctx context.Context, dsn string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedconnectWithDSN(ctx, executionId, dsn)
}

func (c *MySQLClient) ExecuteQueryWithOpts(ctx context.Context, opts MySQLOptions, query string) (*utils.SQLResult, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}

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

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// ແກ້ໄຂ: ປ່ຽນຈາກ db.Query ເປັນ db.QueryContext(ctx, query)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}

	data, err := utils.UnmarshalSQLRows(rows)
	if err != nil {
		if len(data.Rows) > 0 {
			return data, nil
		}
		return nil, err
	}
	return data, nil
}

func (c *MySQLClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, query string) (*utils.SQLResult, error) {
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
