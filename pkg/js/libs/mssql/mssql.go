package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mssql"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	MSSQLClient struct{}
)

func (c *MSSQLClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedconnect(ctx, executionId, host, port, username, password, "master")
}

func (c *MSSQLClient) ConnectWithDB(ctx context.Context, host string, port int, username, password, dbName string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedconnect(ctx, executionId, host, port, username, password, dbName)
}

// @memo
// ແກ້ໄຂ: ເເພີ່ມ ctx ເຂົ້າໃນພາຣາມິເຕີ
func connect(ctx context.Context, executionId string, host string, port int, username string, password string, dbName string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	connString := fmt.Sprintf("sqlserver://%s:%s@%s?database=%s&connection+timeout=30",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName)

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = db.Close()
	}()

	// ແກ້ໄຂ: ປ່ຽນມາໃຊ້ ExecContext ພ້ອມກັບ ctx
	_, err = db.ExecContext(ctx, "select 1")
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "connect: connection refused"):
			fallthrough
		case strings.Contains(err.Error(), "no pg_hba.conf entry for host"):
			fallthrough
		case strings.Contains(err.Error(), "network unreachable"):
			fallthrough
		case strings.Contains(err.Error(), "reset"):
			fallthrough
		case strings.Contains(err.Error(), "i/o timeout"):
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (c *MSSQLClient) IsMssql(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedisMssql(ctx, executionId, host, port)
}

// @memo
// ແກ້ໄຂ: ເເພີ່ມ ctx ເຂົ້າໃນພາຣາມິເຕີ
func isMssql(ctx context.Context, executionId string, host string, port int) (bool, error) {
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

	data, check, err := mssql.DetectMSSQL(conn, 5*time.Second)
	if check && err != nil {
		return false, nil
	} else if !check && err != nil {
		return false, err
	}
	if data.Version != "" {
		return true, nil
	}
	return false, nil
}

func (c *MSSQLClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	executionId := ctx.Value("executionId").(string)
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	ok, err := c.IsMssql(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not a mssql service")
	}

	connString := fmt.Sprintf("sqlserver://%s:%s@%s?database=%s&connection+timeout=30",
		url.PathEscape(username),
		url.PathEscape(password),
		target,
		dbName)

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// ແກ້ໄຂ: ປ່ຽນມາໃຊ້ QueryContext ພ້ອມກັບ ctx
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
