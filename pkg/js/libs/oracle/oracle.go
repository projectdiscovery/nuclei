package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/oracledb"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	goora "github.com/sijms/go-ora/v2"
)

type (
	IsOracleResponse struct {
		IsOracle bool
		Banner   string
	}
	OracleClient struct {
		connector *goora.OracleConnector
	}
)

func (c *OracleClient) IsOracle(ctx context.Context, host string, port int) (IsOracleResponse, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	return memoizedisOracle(ctx, executionId, host, port)
}

// @memo
// ແກ້ໄຂ: ເພີ່ມ ctx ເຂົ້າໃນພາຣາມິເຕີ
func isOracle(ctx context.Context, executionId string, host string, port int) (IsOracleResponse, error) {
	resp := IsOracleResponse{}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsOracleResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	timeout := 5 * time.Second
	// ແກ້ໄຂ: ປ່ຽນ context.TODO() ເປັນ ctx
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	oracledbPlugin := oracledb.ORACLEPlugin{}
	service, err := oracledbPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.Banner = service.Metadata().(plugins.ServiceOracle).Info
	resp.IsOracle = true
	return resp, nil
}

func (c *OracleClient) oracleDbInstance(connStr string, executionId string) (*goora.OracleConnector, error) {
	if c.connector != nil {
		return c.connector, nil
	}

	connector := goora.NewConnector(connStr)
	oraConnector, ok := connector.(*goora.OracleConnector)
	if !ok {
		return nil, fmt.Errorf("failed to cast connector to OracleConnector")
	}

	customDialer := &oracleCustomDialer{
		executionId: executionId,
	}

	oraConnector.Dialer(customDialer)
	c.connector = oraConnector

	return oraConnector, nil
}

func (c *OracleClient) Connect(ctx context.Context, host string, port int, serviceName string, username string, password string) (bool, error) {
	connStr := goora.BuildUrl(host, port, serviceName, username, password, nil)
	return c.ConnectWithDSN(ctx, connStr)
}

func (c *OracleClient) ConnectWithDSN(ctx context.Context, dsn string) (bool, error) {
	executionId := ctx.Value("executionId").(string)

	connector, err := c.oracleDbInstance(dsn, executionId)
	if err != nil {
		return false, err
	}

	db := sql.OpenDB(connector)
	defer func() {
		_ = db.Close()
	}()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// ແກ້ໄຂ: ປ່ຽນມາໃຊ້ PingContext(ctx)
	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *OracleClient) ExecuteQuery(ctx context.Context, host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}

	isOracleResp, err := c.IsOracle(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if !isOracleResp.IsOracle {
		return nil, fmt.Errorf("not a oracle service")
	}

	connStr := goora.BuildUrl(host, port, dbName, username, password, nil)
	return c.ExecuteQueryWithDSN(ctx, connStr, query)
}

func (c *OracleClient) ExecuteQueryWithDSN(ctx context.Context, dsn string, query string) (*utils.SQLResult, error) {
	executionId := ctx.Value("executionId").(string)

	connector, err := c.oracleDbInstance(dsn, executionId)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	defer func() {
		_ = db.Close()
	}()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// ແກ້ໄຂ: ປ່ຽນມາໃຊ້ QueryContext(ctx, query)
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
