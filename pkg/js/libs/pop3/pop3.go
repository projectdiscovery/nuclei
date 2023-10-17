package pop3

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/pop3"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Pop3Client is a minimal POP3 client for nuclei scripts.
type Pop3Client struct{}

// IsPOP3Response is the response from the IsPOP3 function.
type IsPOP3Response struct {
	IsPOP3 bool
	Banner string
}

// IsPOP3 checks if a host is running a POP3 server.
func (c *Pop3Client) IsPOP3(host string, port int) (IsPOP3Response, error) {
	resp := IsPOP3Response{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	pop3Plugin := pop3.POP3Plugin{}
	service, err := pop3Plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Metadata().(plugins.ServicePOP3).Banner
	resp.IsPOP3 = true
	return resp, nil
}
