package smb

import (
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

// Client is a client for SMB servers.
//
// Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
// github.com/hirochachacha/go-smb2 driver
type Client struct{}

// ConnectSMBInfoMode tries to connect to provided host and port
// and discovery SMB information
//
// Returns handshake log and error. If error is not nil,
// state will be false
func (c *Client) ConnectSMBInfoMode(host string, port int) (*smb.SMBLog, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	setupSession := true

	result, err := smb.GetSMBLog(conn, setupSession, false, false)
	if err != nil {
		conn.Close()
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
		if err != nil {
			return nil, err
		}
		result, err = smb.GetSMBLog(conn, setupSession, true, false)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// ListSMBv2Metadata tries to connect to provided host and port
// and list SMBv2 metadata.
//
// Returns metadata and error. If error is not nil,
// state will be false
func (c *Client) ListSMBv2Metadata(host string, port int) (*plugins.ServiceSMB, error) {
	return collectSMBv2Metadata(host, port, 5*time.Second)
}

// ListShares tries to connect to provided host and port
// and list shares by using given credentials.
//
// Credentials cannot be blank. guest or anonymous credentials
// can be used by providing empty password.
func (c *Client) ListShares(host string, port int, user, password string) ([]string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: password,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		return nil, err
	}
	return names, nil
}
