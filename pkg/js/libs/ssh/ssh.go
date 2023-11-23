package ssh

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/zmap/zgrab2/lib/ssh"
)

// SSHClient is a client for SSH servers.
//
// Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
type SSHClient struct {
	Connection *ssh.Client
}

// Connect tries to connect to provided host and port
// with provided username and password with ssh.
//
// Returns state of connection and error. If error is not nil,
// state will be false
func (c *SSHClient) Connect(host string, port int, username, password string) (bool, error) {
	conn, err := connect(host, port, username, password, "")
	if err != nil {
		return false, err
	}
	c.Connection = conn

	return true, nil
}

// ConnectWithKey tries to connect to provided host and port
// with provided username and private_key.
//
// Returns state of connection and error. If error is not nil,
// state will be false
func (c *SSHClient) ConnectWithKey(host string, port int, username, key string) (bool, error) {
	conn, err := connect(host, port, username, "", key)
	if err != nil {
		return false, err
	}
	c.Connection = conn

	return true, nil
}

// ConnectSSHInfoMode tries to connect to provided host and port
// with provided host and port
//
// Returns HandshakeLog and error. If error is not nil,
// state will be false
//
// HandshakeLog is a struct that contains information about the
// ssh connection
func (c *SSHClient) ConnectSSHInfoMode(host string, port int) (*ssh.HandshakeLog, error) {
	return connectSSHInfoMode(host, port)
}

// Run tries to open a new SSH session, then tries to execute
// the provided command in said session
//
// Returns string and error. If error is not nil,
// state will be false
//
// The string contains the command output
func (c *SSHClient) Run(cmd string) (string, error) {
	if c.Connection == nil {
		return "", errorutil.New("no connection")
	}
	session, err := c.Connection.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	data, err := session.Output(cmd)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Close closes the SSH connection and destroys the client
//
// Returns the success state and error. If error is not nil,
// state will be false
func (c *SSHClient) Close() (bool, error) {
	if err := c.Connection.Close(); err != nil {
		return false, err
	}
	return true, nil
}

func connectSSHInfoMode(host string, port int) (*ssh.HandshakeLog, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	data := new(ssh.HandshakeLog)

	sshConfig := ssh.MakeSSHConfig()
	sshConfig.Timeout = 10 * time.Second
	sshConfig.ConnLog = data
	sshConfig.DontAuthenticate = true
	sshConfig.BannerCallback = func(banner string) error {
		data.Banner = strings.TrimSpace(banner)
		return nil
	}
	rhost := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", rhost, sshConfig)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return data, nil
}

func connect(host string, port int, user, password, privateKey string) (*ssh.Client, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	if host == "" || port <= 0 {
		return nil, errors.New("invalid host or port")
	}

	conf := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{},
	}
	if len(password) > 0 {
		conf.Auth = append(conf.Auth, ssh.Password(password))
	}
	if len(privateKey) > 0 {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, err
		}
		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), conf)
	if err != nil {
		return nil, err
	}
	return client, nil
}
