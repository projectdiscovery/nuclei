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
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	go_ora "github.com/sijms/go-ora/v2"
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
	// const client = new oracle.OracleClient;
	// ```
	OracleClient struct{}
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

// Connect connects to an Oracle database
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const client = new oracle.OracleClient;
// client.Connect('acme.com', 1521, 'XE', 'user', 'password');
// ```
func (c *OracleClient) Connect(ctx context.Context, host string, port int, serviceName string, username string, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)

	connStr := goora.BuildUrl(host, port, serviceName, username, password, nil)

	connector := goora.NewConnector(connStr)
	oraConnector, ok := connector.(*go_ora.OracleConnector)
	if !ok {
		return false, fmt.Errorf("failed to cast connector to OracleConnector")
	}

	// Create custom dialer wrapper
	customDialer := &oracleCustomDialer{
		executionId: executionId,
	}

	oraConnector.Dialer(customDialer)
	db := sql.OpenDB(connector)
	defer db.Close()

	// Test the connection
	err := db.Ping()
	if err != nil {
		return false, err
	}

	return true, nil
}
