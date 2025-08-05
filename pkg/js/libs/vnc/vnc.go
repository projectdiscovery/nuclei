package vnc

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/vnc"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
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
func IsVNC(ctx context.Context, host string, port int) (IsVNCResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisVNC(executionId, host, port)
}

// @memo
func isVNC(executionId string, host string, port int) (IsVNCResponse, error) {
	resp := IsVNCResponse{}

	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsVNCResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

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
