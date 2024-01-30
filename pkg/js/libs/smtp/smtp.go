package smtp

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"

	pluginsmtp "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smtp"
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

	smtpPlugin := pluginsmtp.SMTPPlugin{}
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

func (c *SMTPClient) IsOpenRelay(host string, port int, msg *SMTPMessage) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	if err := client.Mail(msg.from); err != nil {
		return false, err
	}
	if len(msg.to) == 0 || len(msg.to) > 1 {
		return false, fmt.Errorf("invalid number of recipients: required 1, got %d", len(msg.to))
	}
	if err := client.Rcpt(msg.to[0]); err != nil {
		return false, err
	}

	// Send the email body.
	wc, err := client.Data()
	if err != nil {
		return false, err
	}

	_, err = wc.Write([]byte(msg.String()))
	if err != nil {
		return false, err
	}
	err = wc.Close()
	if err != nil {
		return false, err
	}
	// Send the QUIT command and close the connection.
	err = client.Quit()
	if err != nil {
		return false, err
	}
	return true, nil
}

// SendMail sends an email using the SMTP protocol.
func (c *SMTPClient) SendMail(host string, port string, msg *SMTPMessage) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	var auth smtp.Auth
	if msg.user != "" && msg.pass != "" {
		auth = smtp.PlainAuth("", msg.user, msg.pass, host)
	}

	// send mail
	addr := net.JoinHostPort(host, port)
	if err := smtp.SendMail(addr, auth, msg.from, msg.to, []byte(msg.String())); err != nil {
		return false, err
	}
	return true, nil
}
