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
	// IsOracleResponse is the response from the IsOracle function.
	// this is returned by IsOracle function.
	// @example
	// ```javascript
	// const oracle = require('nuclei/oracle');
	// const isOracle = oracle.IsOracle('acme.com', 1521);
	// ```
	IsOracleResponse struct {
		IsOracle bool
		Banner   string
	}
	// Client is a client for Oracle database.
	// Internally client uses oracle/godror driver.
	// @example
	// ```javascript
	// const oracle = require('nuclei/oracle');
	// const client = new oracle.OracleClient();
	// ```
	OracleClient struct {
		connector *goora.OracleConnector
	}
)

// IsOracle checks if a host is running an Oracle server
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const isOracle = oracle.IsOracle('acme.com', 1521);
// log(toJSON(isOracle));
// ```
func (c *OracleClient) IsOracle(ctx context.Context, host string, port int) (IsOracleResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisOracle(executionId, host, port)
}

// @memo
func isOracle(executionId string, host string, port int) (IsOracleResponse, error) {
	resp := IsOracleResponse{}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsOracleResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	timeout := 5 * time.Second
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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

	// Create custom dialer wrapper
	customDialer := &oracleCustomDialer{
		executionId: executionId,
	}

	oraConnector.Dialer(customDialer)

	c.connector = oraConnector

	return oraConnector, nil
}

// Connect connects to an Oracle database
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const client = new oracle.OracleClient;
// client.Connect('acme.com', 1521, 'XE', 'user', 'password');
// ```
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

	// Test the connection
	err = db.Ping()
	if err != nil {
		return false, err
	}

	return true, nil
}

// ExecuteQuery connects to MS SQL database using given credentials and executes a query.
// It returns the results of the query or an error if something goes wrong.
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const client = new oracle.OracleClient;
// const result = client.ExecuteQuery('acme.com', 1521, 'username', 'password', 'XE', 'SELECT @@version');
// log(to_json(result));
// ```
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

// ExecuteQueryWithDSN executes a query on an Oracle database using a DSN
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const client = new oracle.OracleClient;
// const result = client.ExecuteQueryWithDSN('oracle://user:password@host:port/service', 'SELECT @@version');
// log(to_json(result));
// ```
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

	rows, err := db.Query(query)
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
