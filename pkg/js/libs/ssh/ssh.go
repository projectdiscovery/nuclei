package ssh

import (
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
	timeout    time.Duration
}

// SetTimeout sets the timeout for the SSH connection in seconds
func (c *SSHClient) SetTimeout(sec int) {
	c.timeout = time.Duration(sec) * time.Second
}

// Connect tries to connect to provided host and port
// with provided username and password with ssh.
//
// Returns state of connection and error. If error is not nil,
// state will be false
func (c *SSHClient) Connect(host string, port int, username, password string) (bool, error) {
	conn, err := connect(&connectOptions{
		Host:     host,
		Port:     port,
		User:     username,
		Password: password,
	})
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
	conn, err := connect(&connectOptions{
		Host:       host,
		Port:       port,
		User:       username,
		PrivateKey: key,
	})

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
	return connectSSHInfoMode(&connectOptions{
		Host: host,
		Port: port,
	})
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

// unexported functions
type connectOptions struct {
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey string
	Timeout    time.Duration // default 10s
}

func (c *connectOptions) validate() error {
	if c.Host == "" {
		return errorutil.New("host is required")
	}
	if c.Port <= 0 {
		return errorutil.New("port is required")
	}
	if !protocolstate.IsHostAllowed(c.Host) {
		// host is not valid according to network policy
		return protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	return nil
}

func connectSSHInfoMode(opts *connectOptions) (*ssh.HandshakeLog, error) {
	if err := opts.validate(); err != nil {
		return nil, err
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
	rhost := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	client, err := ssh.Dial("tcp", rhost, sshConfig)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return data, nil
}

func connect(opts *connectOptions) (*ssh.Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	conf := &ssh.ClientConfig{
		User:    opts.User,
		Auth:    []ssh.AuthMethod{},
		Timeout: opts.Timeout,
	}
	if len(opts.Password) > 0 {
		conf.Auth = append(conf.Auth, ssh.Password(opts.Password))
	}
	if len(opts.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey([]byte(opts.PrivateKey))
		if err != nil {
			return nil, err
		}
		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), conf)
	if err != nil {
		return nil, err
	}
	return client, nil
}
