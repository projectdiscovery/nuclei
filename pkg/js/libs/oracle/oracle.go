package oracle

import (
	"context"
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
func IsOracle(host string, port int) (IsOracleResponse, error) {
	return memoizedisOracle(host, port)
}

// @memo
func isOracle(host string, port int) (IsOracleResponse, error) {
	resp := IsOracleResponse{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

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
