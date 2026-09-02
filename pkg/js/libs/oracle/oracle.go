package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
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

	// OracleOptions defines the connection options for an Oracle database.
	OracleOptions struct {
		Host        string
		Port        int
		ServiceName string
		Username    string
		Password    string
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
	return memoizedisOracle(ctx, executionId, host, port)
}

// @memo
func isOracle(ctx context.Context, executionId string, host string, port int) (IsOracleResponse, error) {
	resp := IsOracleResponse{}
	if !protocolstate.IsHostAllowed(executionId, host) {
		return resp, protocolstate.ErrHostDenied.Msgf(host)
	}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsOracleResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	timeout := 5 * time.Second
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

func (c *OracleClient) oracleDbInstance(ctx context.Context, connStr string, executionId string) (*goora.OracleConnector, error) {
	connStr, err := sandboxDSN(executionId, connStr)
	if err != nil {
		return nil, err
	}
	config, err := goora.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}
	for _, server := range config.Servers {
		if !protocolstate.IsHostAllowed(executionId, server.Addr) {
			return nil, protocolstate.ErrHostDenied.Msgf(server.Addr)
		}
	}

	connector := goora.NewConnector(connStr)
	oraConnector, ok := connector.(*goora.OracleConnector)
	if !ok {
		return nil, fmt.Errorf("failed to cast connector to OracleConnector")
	}
	// A connector embeds its DSN, so replace it for each invocation to ensure
	// option changes and the sandboxed DSN are applied to the actual dial.
	c.connector = oraConnector

	// Refresh the dialer on every call so the connector uses the current
	// execution context instead of a stale or already-canceled one.
	c.connector.Dialer(&oracleCustomDialer{executionId: executionId, ctx: ctx})

	return c.connector, nil
}

func sandboxDSN(executionId string, dsn string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	changed := false
	for key, values := range query {
		if !isOracleTracePathOption(key) {
			continue
		}
		for i, value := range values {
			if value == "" {
				continue
			}
			normalized, err := protocolstate.NormalizePathWithExecutionId(executionId, value)
			if err != nil {
				return "", fmt.Errorf("oracle %s %q: %w", key, value, err)
			}
			values[i] = normalized
		}
		query[key] = values
		changed = true
	}
	if !changed {
		return dsn, nil
	}

	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func isOracleTracePathOption(key string) bool {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "TRACE FILE", "TRACE DIR", "TRACE FOLDER", "TRACE DIRECTORY":
		return true
	default:
		return false
	}
}

// Connect connects to an Oracle database.
//
// Deprecated: prefer ConnectWithOptions for new templates.
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const client = new oracle.OracleClient;
// client.Connect('acme.com', 1521, 'XE', 'user', 'password');
// ```
func (c *OracleClient) Connect(ctx context.Context, host string, port int, serviceName string, username string, password string) (bool, error) {
	return c.ConnectWithOptions(ctx, OracleOptions{
		Host: host, Port: port, ServiceName: serviceName, Username: username, Password: password,
	})
}

// ConnectWithOptions connects to Oracle using the supplied connection options.
func (c *OracleClient) ConnectWithOptions(ctx context.Context, opts OracleOptions) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	if opts.Host == "" || opts.Port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		return false, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}
	connStr, err := buildOracleDSN(opts)
	if err != nil {
		return false, err
	}
	return c.ConnectWithDSN(ctx, connStr)
}

func (c *OracleClient) ConnectWithDSN(ctx context.Context, dsn string) (bool, error) {
	executionId := ctx.Value("executionId").(string)

	connector, err := c.oracleDbInstance(ctx, dsn, executionId)
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
	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
}

func buildOracleDSN(opts OracleOptions) (string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return "", fmt.Errorf("invalid host or port")
	}
	if opts.ServiceName == "" {
		return "", fmt.Errorf("service name cannot be empty")
	}
	return goora.BuildUrl(opts.Host, opts.Port, opts.ServiceName, opts.Username, opts.Password, nil), nil
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

	connector, err := c.oracleDbInstance(ctx, dsn, executionId)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	defer func() {
		_ = db.Close()
	}()

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
