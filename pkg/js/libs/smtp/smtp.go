package smtp

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smtp"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// SMTPClient is a minimal SMTP client for nuclei scripts.
type SMTPClient struct{}

// IsSMTPResponse is the response from the IsSMTP function.
type IsSMTPResponse struct {
	IsSMTP bool
	Banner string
}

// IsSMTP checks if a host is running a SMTP server.
func (c *SMTPClient) IsSMTP(host string, port int) (IsSMTPResponse, error) {
	resp := IsSMTPResponse{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	smtpPlugin := smtp.SMTPPlugin{}
	service, err := smtpPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.IsSMTP = true
	return resp, nil
}
