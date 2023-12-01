package smtp

import (
    "context"
    "fmt"
    "strings"
    "net"
    "strconv"
    "time"
    "net/smtp"

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


func (c *SMTPClient) IsOpenRelay(host string, port int, from string, to string, subj string, msg []byte) (bool, error) {
    con, err := smtp.Dial(net.JoinHostPort(host, strconv.Itoa(port)))
    if err != nil {
        return false, err
    }

    if err := con.Mail(from); err != nil {
        return false, err
    }
    if err := con.Rcpt(to); err != nil {
        return false, err
    }

    // Send the email body.
    wc, err := con.Data()
    if err != nil {
        return false, err
    }

    formattedSubj := fmt.Sprintf(subj, net.JoinHostPort(host, strconv.Itoa(port)))
    formattedMsg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", to, formattedSubj, msg)

    _, err = fmt.Fprintf(wc, formattedMsg)
    if err != nil {
        return false, err
    }
    err = wc.Close()
    if err != nil {
        return false, err
    }

    // Send the QUIT command and close the connection.
    err = con.Quit()
    if err != nil {
        return false, err
    }

    return true, nil
}

func (c *SMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, subj string, msg []byte) (bool, error) {

    // Connect to the server, authenticate, set the sender and recipient,
    // and send the email all in one step.
    formattedMsg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", strings.Join(to, ","), subj, msg)

    if err := smtp.SendMail(addr, a, from, to, []byte(formattedMsg)); err != nil {
        return false, err
    }

    return true, nil
}
