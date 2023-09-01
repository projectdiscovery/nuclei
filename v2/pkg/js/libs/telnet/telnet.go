package telnet

import (
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/telnet"
)

// Client is a minimal Telnet client for nuclei scripts.
type Client struct{}

// IsTelnetResponse is the response from the IsTelnet function.
type IsTelnetResponse struct {
	IsTelnet bool
	Banner   string
}

// IsTelnet checks if a host is running a Telnet server.
func (c *Client) IsTelnet(host string, port int) (IsTelnetResponse, error) {
	resp := IsTelnetResponse{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
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
