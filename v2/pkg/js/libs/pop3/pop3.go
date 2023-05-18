package pop3

import (
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/pop3"
)

// Client is a minimal POP3 client for nuclei scripts.
type Client struct{}

// IsPOP3Response is the response from the IsPOP3 function.
type IsPOP3Response struct {
	IsPOP3 bool
	Banner string
}

// IsPOP3 checks if a host is running a POP3 server.
func (c *Client) IsPOP3(host string, port int) (IsPOP3Response, error) {
	resp := IsPOP3Response{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	pop3Plugin := pop3.POP3Plugin{}
	service, err := pop3Plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	resp.Banner = service.Version
	resp.IsPOP3 = true
	return resp, nil
}
