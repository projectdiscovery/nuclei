package smtp

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/dop251/goja"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"

	pluginsmtp "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smtp"
)

type (
	// SMTPResponse is the response from the IsSMTP function.
	// @example
	// ```javascript
	// const smtp = require('nuclei/smtp');
	// const client = new smtp.Client('acme.com', 25);
	// const isSMTP = client.IsSMTP();
	// log(isSMTP)
	// ```
	SMTPResponse struct {
		IsSMTP bool
		Banner string
	}
)

type (
	// Client is a minimal SMTP client for nuclei scripts.
	// @example
	// ```javascript
	// const smtp = require('nuclei/smtp');
	// const client = new smtp.Client('acme.com', 25);
	// ```
	Client struct {
		nj   *utils.NucleiJS
		host string
		port string
	}
)

// Constructor for SMTP Client
// Constructor: constructor(public host: string, public port: string)
func NewSMTPClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	// setup nucleijs utils
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(host, port)" // will be included in error messages

	host, _ := c.nj.GetArg(call.Arguments, 0).(string) // host
	port, _ := c.nj.GetArg(call.Arguments, 1).(string) // port

	// validate arguments
	c.nj.Require(host != "", "host cannot be empty")
	c.nj.Require(port != "", "port cannot be empty")

	// validate port
	portInt, err := strconv.Atoi(port)
	c.nj.Require(err == nil && portInt > 0 && portInt < 65536, "port must be a valid number")
	c.host = host
	c.port = port

	// check if this is allowed address
	c.nj.Require(protocolstate.IsHostAllowed(host+":"+port), protocolstate.ErrHostDenied.Msgf(host+":"+port).Error())

	// Link Constructor to Client and return
	return utils.LinkConstructor(call, runtime, c)
}

// IsSMTP checks if a host is running a SMTP server.
// @example
// ```javascript
// const smtp = require('nuclei/smtp');
// const client = new smtp.Client('acme.com', 25);
// const isSMTP = client.IsSMTP();
// log(isSMTP)
// ```
func (c *Client) IsSMTP() (SMTPResponse, error) {
	resp := SMTPResponse{}
	c.nj.Require(c.host != "", "host cannot be empty")
	c.nj.Require(c.port != "", "port cannot be empty")

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(c.host, c.port))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	smtpPlugin := pluginsmtp.SMTPPlugin{}
	service, err := smtpPlugin.Run(conn, timeout, plugins.Target{Host: c.host})
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

// IsOpenRelay checks if a host is an open relay.
// @example
// ```javascript
// const smtp = require('nuclei/smtp');
// const message = new smtp.SMTPMessage();
// message.From('xyz@projectdiscovery.io');
// message.To('xyz2@projectdiscoveyr.io');
// message.Subject('hello');
// message.Body('hello');
// const client = new smtp.Client('acme.com', 25);
// const isRelay = client.IsOpenRelay(message);
// ```
func (c *Client) IsOpenRelay(msg *SMTPMessage) (bool, error) {
	c.nj.Require(c.host != "", "host cannot be empty")
	c.nj.Require(c.port != "", "port cannot be empty")

	addr := net.JoinHostPort(c.host, c.port)
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, c.host)
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
// @example
// ```javascript
// const smtp = require('nuclei/smtp');
// const message = new smtp.SMTPMessage();
// message.From('xyz@projectdiscovery.io');
// message.To('xyz2@projectdiscoveyr.io');
// message.Subject('hello');
// message.Body('hello');
// const client = new smtp.Client('acme.com', 25);
// const isSent = client.SendMail(message);
// log(isSent)
// ```
func (c *Client) SendMail(msg *SMTPMessage) (bool, error) {
	c.nj.Require(c.host != "", "host cannot be empty")
	c.nj.Require(c.port != "", "port cannot be empty")

	var auth smtp.Auth
	if msg.user != "" && msg.pass != "" {
		auth = smtp.PlainAuth("", msg.user, msg.pass, c.host)
	}

	// send mail
	addr := net.JoinHostPort(c.host, c.port)
	if err := smtp.SendMail(addr, auth, msg.from, msg.to, []byte(msg.String())); err != nil {
		c.nj.Throw("failed to send mail with message(%s) got %v", msg.String(), err)
	}
	return true, nil
}
