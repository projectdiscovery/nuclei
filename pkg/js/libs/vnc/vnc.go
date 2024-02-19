package vnc

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/vnc"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// VNCClient is a minimal VNC client for nuclei scripts.
	// @example
	// ```javascript
	// const vnc = require('nuclei/vnc');
	// const client = new vnc.Client();
	// ```
	VNCClient struct{}
)

type (
	// IsVNCResponse is the response from the IsVNC function.
	// @example
	// ```javascript
	// const vnc = require('nuclei/vnc');
	// const isVNC = vnc.IsVNC('acme.com', 5900);
	// log(toJSON(isVNC));
	// ```
	IsVNCResponse struct {
		IsVNC  bool
		Banner string
	}
)

// IsVNC checks if a host is running a VNC server.
// It returns a boolean indicating if the host is running a VNC server
// and the banner of the VNC server.
// @example
// ```javascript
// const vnc = require('nuclei/vnc');
// const isVNC = vnc.IsVNC('acme.com', 5900);
// log(toJSON(isVNC));
// ```
func (c *VNCClient) IsVNC(host string, port int) (IsVNCResponse, error) {
	return memoizedIsVnc(host, port)
}

// @memo
func isVnc(host string, port int) (IsVNCResponse, error) {
	resp := IsVNCResponse{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	vncPlugin := vnc.VNCPlugin{}
	service, err := vncPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.IsVNC = true
	return resp, nil
}
