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

// VNCClient is a minimal VNC client for nuclei scripts.
type VNCClient struct{}

// IsVNCResponse is the response from the IsVNC function.
type IsVNCResponse struct {
	IsVNC  bool
	Banner string
}

// IsVNC checks if a host is running a VNC server.
// It returns a boolean indicating if the host is running a VNC server
// and the banner of the VNC server.
func (c *VNCClient) IsVNC(host string, port int) (IsVNCResponse, error) {
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
