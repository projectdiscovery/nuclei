package oracle

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/oracledb"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
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
)

// IsOracle checks if a host is running an Oracle server
// @example
// ```javascript
// const oracle = require('nuclei/oracle');
// const isOracle = oracle.IsOracle('acme.com', 1521);
// log(toJSON(isOracle));
// ```
func IsOracle(ctx context.Context, host string, port int) (IsOracleResponse, error) {
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
