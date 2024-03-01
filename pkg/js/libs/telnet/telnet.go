package telnet

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/telnet"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// IsTelnetResponse is the response from the IsTelnet function.
	// this is returned by IsTelnet function.
	// @example
	// ```javascript
	// const telnet = require('nuclei/telnet');
	// const isTelnet = telnet.IsTelnet('acme.com', 23);
	// log(toJSON(isTelnet));
	// ```
	IsTelnetResponse struct {
		IsTelnet bool
		Banner   string
	}
)

// IsTelnet checks if a host is running a Telnet server.
// @example
// ```javascript
// const telnet = require('nuclei/telnet');
// const isTelnet = telnet.IsTelnet('acme.com', 23);
// log(toJSON(isTelnet));
// ```
func IsTelnet(host string, port int) (IsTelnetResponse, error) {
	return memoizedisTelnet(host, port)
}

// @memo
func isTelnet(host string, port int) (IsTelnetResponse, error) {
	resp := IsTelnetResponse{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	telnetPlugin := telnet.TELNETPlugin{}
	service, err := telnetPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Metadata().(plugins.ServiceTelnet).ServerData
	resp.IsTelnet = true
	return resp, nil
}
