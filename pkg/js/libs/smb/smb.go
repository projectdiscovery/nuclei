package smb

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/go-smb2"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

type (
	// SMBClient is a client for SMB servers.
	// Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
	// github.com/projectdiscovery/go-smb2 driver
	// @example
	// ```javascript
	// const smb = require('nuclei/smb');
	// const client = new smb.SMBClient();
	// ```
	SMBClient struct{}
)

// ConnectSMBInfoMode tries to connect to provided host and port
// and discovery SMB information
// Returns handshake log and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const info = client.ConnectSMBInfoMode('acme.com', 445);
// log(to_json(info));
// ```
func (c *SMBClient) ConnectSMBInfoMode(host string, port int) (*smb.SMBLog, error) {
	return memoizedconnectSMBInfoMode(host, port)
}

// @memo
func connectSMBInfoMode(host string, port int) (*smb.SMBLog, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	// try to get SMBv2/v3 info
	result, err := getSMBInfo(conn, true, false)
	_ = conn.Close() // close regardless of error
	if err == nil {
		return result, nil
	}

	// try to negotiate SMBv1
	conn, err = protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	result, err = getSMBInfo(conn, true, true)
	if err != nil {
		return result, nil
	}
	return result, nil
}

// ListSMBv2Metadata tries to connect to provided host and port
// and list SMBv2 metadata.
// Returns metadata and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const metadata = client.ListSMBv2Metadata('acme.com', 445);
// log(to_json(metadata));
// ```
func (c *SMBClient) ListSMBv2Metadata(host string, port int) (*plugins.ServiceSMB, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	return memoizedcollectSMBv2Metadata(host, port, 5*time.Second)
}

// ListShares tries to connect to provided host and port
// and list shares by using given credentials.
// Credentials cannot be blank. guest or anonymous credentials
// can be used by providing empty password.
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const shares = client.ListShares('acme.com', 445, 'username', 'password');
//
//	for (const share of shares) {
//		  log(share);
//	}
//
// ```
func (c *SMBClient) ListShares(host string, port int, user, password string) ([]string, error) {
	return memoizedlistShares(host, port, user, password)
}

// @memo
func listShares(host string, port int, user string, password string) ([]string, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
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
	defer func() {
		_ = s.Logoff()
	}()

	names, err := s.ListSharenames()
	if err != nil {
		return nil, err
	}
	return names, nil
}
