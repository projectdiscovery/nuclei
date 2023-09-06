package oracle

import (
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/oracledb"
)

// OracleClient is a minimal Oracle client for nuclei scripts.
type OracleClient struct{}

// IsOracleResponse is the response from the IsOracle function.
type IsOracleResponse struct {
	IsOracle bool
	Banner   string
}

// IsOracle checks if a host is running an Oracle server.
func (c *OracleClient) IsOracle(host string, port int) (IsOracleResponse, error) {
	resp := IsOracleResponse{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
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
