package ssh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/zmap/zgrab2/lib/ssh"
)

type (
	// SSHClient is a client for SSH servers.
	// Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
	// @example
	// ```javascript
	// const ssh = require('nuclei/ssh');
	// const client = new ssh.SSHClient();
	// ```
	SSHClient struct {
		connection *ssh.Client
		timeout    time.Duration
	}
)

// SetTimeout sets the timeout for the SSH connection in seconds
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// client.SetTimeout(10);
// ```
func (c *SSHClient) SetTimeout(sec int) {
	c.timeout = time.Duration(sec) * time.Second
}

// Connect tries to connect to provided host and port
// with provided username and password with ssh.
// Returns state of connection and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const connected = client.Connect('acme.com', 22, 'username', 'password');
// ```
func (c *SSHClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	conn, err := connect(&connectOptions{
		Host:        host,
		Port:        port,
		User:        username,
		Password:    password,
		ExecutionId: executionId,
	})
	if err != nil {
		return false, err
	}
	c.connection = conn

	return true, nil
}

// ConnectWithKey tries to connect to provided host and port
// with provided username and private_key.
// Returns state of connection and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const privateKey = `-----BEGIN RSA PRIVATE KEY----- ...`;
// const connected = client.ConnectWithKey('acme.com', 22, 'username', privateKey);
// ```
func (c *SSHClient) ConnectWithKey(ctx context.Context, host string, port int, username, key string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	conn, err := connect(&connectOptions{
		Host:        host,
		Port:        port,
		User:        username,
		PrivateKey:  key,
		ExecutionId: executionId,
	})

	if err != nil {
		return false, err
	}
	c.connection = conn

	return true, nil
}

// ConnectSSHInfoMode tries to connect to provided host and port
// with provided host and port
// Returns HandshakeLog and error. If error is not nil,
// state will be false
// HandshakeLog is a struct that contains information about the
// ssh connection
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const info = client.ConnectSSHInfoMode('acme.com', 22);
// log(to_json(info));
// ```
func (c *SSHClient) ConnectSSHInfoMode(ctx context.Context, host string, port int) (*ssh.HandshakeLog, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnectSSHInfoMode(&connectOptions{
		Host:        host,
		Port:        port,
		ExecutionId: executionId,
	})
}

// Run tries to open a new SSH session, then tries to execute
// the provided command in said session
// Returns string and error. If error is not nil,
// state will be false
// The string contains the command output
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// client.Connect('acme.com', 22, 'username', 'password');
// const output = client.Run('id');
// log(output);
// ```
func (c *SSHClient) Run(cmd string) (string, error) {
	if c.connection == nil {
		return "", errkit.New("no connection")
	}
	session, err := c.connection.NewSession()
	if err != nil {
		return "", err
	}
	defer func() {
		_ = session.Close()
	}()

	data, err := session.Output(cmd)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Close closes the SSH connection and destroys the client
// Returns the success state and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// client.Connect('acme.com', 22, 'username', 'password');
// const closed = client.Close();
// ```
func (c *SSHClient) Close() (bool, error) {
	if err := c.connection.Close(); err != nil {
		return false, err
	}
	return true, nil
}

// unexported functions
type connectOptions struct {
	Host        string
	Port        int
	User        string
	Password    string
	PrivateKey  string
	Timeout     time.Duration // default 10s
	ExecutionId string
}

func (c *connectOptions) validate() error {
	if c.Host == "" {
		return errkit.New("host is required")
	}
	if c.Port <= 0 {
		return errkit.New("port is required")
	}
	if !protocolstate.IsHostAllowed(c.ExecutionId, c.Host) {
		// host is not valid according to network policy
		return protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	return nil
}

// @memo
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
	defer func() {
		_ = client.Close()
	}()

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

		cb := func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			if len(questions) == 1 {
				return []string{opts.Password}, nil
			}
			return []string{}, nil
		}
		conf.Auth = append(conf.Auth, ssh.KeyboardInteractiveChallenge(cb))
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
