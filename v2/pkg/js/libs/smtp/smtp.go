package smtp

import (
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smtp"
)

// Client is a minimal SMTP client for nuclei scripts.
type Client struct{}

// IsSMTPResponse is the response from the IsSMTP function.
type IsSMTPResponse struct {
	IsSMTP bool
	Banner string
}

// IsSMTP checks if a host is running a SMTP server.
func (c *Client) IsSMTP(host string, port int) (IsSMTPResponse, error) {
	resp := IsSMTPResponse{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
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
