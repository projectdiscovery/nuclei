package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
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

// precompiled regex patterns
var (
	passwordQuestionPattern = regexp.MustCompile(`(?i)(pass(word|phrase|code)?|pin)`)
	usernameQuestionPattern = regexp.MustCompile(`(?i)(user(name)?|login)`)
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

type (
	// SSHOptions represents configuration options for an SSH connection.
	// Use ConnectWithOptions when you need protocol-specific knobs beyond
	// username/password (timeout, client version, private key).
	// @example
	// ```javascript
	// const ssh = require('nuclei/ssh');
	// const client = new ssh.SSHClient();
	// const opts = new ssh.SSHOptions();
	// opts.Host = 'acme.com';
	// opts.Port = 22;
	// opts.User = 'username';
	// opts.Password = 'password';
	// opts.Timeout = 15;
	// opts.ClientVersion = 'SSH-2.0-OpenSSH_8.9';
	// const connected = client.ConnectWithOptions(opts);
	// ```
	SSHOptions struct {
		Host          string // Host is the hostname or IP of the SSH server.
		Port          int    // Port is the port number of the SSH server.
		User          string // User is the username for authentication.
		Password      string // Password is the password for authentication.
		PrivateKey    string // PrivateKey is an optional PEM-encoded private key.
		Timeout       int    // Timeout is the connection timeout in seconds (default 10).
		ClientVersion string // ClientVersion overrides the SSH client version string (e.g. "SSH-2.0-OpenSSH_8.9").
	}
)

// ConnectWithOptions tries to connect using the provided SSHOptions.
// Prefer this over Connect/ConnectWithKey when setting timeout, client version,
// or combining password and private key auth.
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const opts = new ssh.SSHOptions();
// opts.Host = 'acme.com';
// opts.Port = 22;
// opts.User = 'username';
// opts.Password = 'password';
// const connected = client.ConnectWithOptions(opts);
// ```
func (c *SSHClient) ConnectWithOptions(ctx context.Context, opts SSHOptions) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	copts := optionsToConnect(opts, executionId)
	if c.timeout > 0 && copts.Timeout == 0 {
		copts.Timeout = c.timeout
	}
	conn, err := connect(copts)
	if err != nil {
		return false, err
	}
	c.connection = conn
	return true, nil
}

func optionsToConnect(opts SSHOptions, executionId string) *connectOptions {
	copts := &connectOptions{
		Host:          opts.Host,
		Port:          opts.Port,
		User:          opts.User,
		Password:      opts.Password,
		PrivateKey:    opts.PrivateKey,
		ClientVersion: opts.ClientVersion,
		ExecutionId:   executionId,
	}
	if opts.Timeout > 0 {
		copts.Timeout = time.Duration(opts.Timeout) * time.Second
	}
	return copts
}

// Connect tries to connect to provided host and port
// with provided username and password with ssh.
// Returns state of connection and error. If error is not nil,
// state will be false
//
// Deprecated: prefer ConnectWithOptions for new templates.
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const connected = client.Connect('acme.com', 22, 'username', 'password');
// ```
func (c *SSHClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	return c.ConnectWithOptions(ctx, SSHOptions{
		Host:     host,
		Port:     port,
		User:     username,
		Password: password,
	})
}

// ConnectWithKey tries to connect to provided host and port
// with provided username and private_key.
// Returns state of connection and error. If error is not nil,
// state will be false
//
// Deprecated: prefer ConnectWithOptions (set PrivateKey) for new templates.
// @example
// ```javascript
// const ssh = require('nuclei/ssh');
// const client = new ssh.SSHClient();
// const privateKey = `-----BEGIN RSA PRIVATE KEY----- ...`;
// const connected = client.ConnectWithKey('acme.com', 22, 'username', privateKey);
// ```
func (c *SSHClient) ConnectWithKey(ctx context.Context, host string, port int, username, key string) (bool, error) {
	return c.ConnectWithOptions(ctx, SSHOptions{
		Host:       host,
		Port:       port,
		User:       username,
		PrivateKey: key,
	})
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
	Host          string
	Port          int
	User          string
	Password      string
	PrivateKey    string
	Timeout       time.Duration // default 10s
	ClientVersion string
	ExecutionId   string
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
	client, err := dialSSH(context.Background(), opts.ExecutionId, rhost, sshConfig)
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
		User:          opts.User,
		Auth:          []ssh.AuthMethod{},
		Timeout:       opts.Timeout,
		ClientVersion: opts.ClientVersion,
	}

	if len(opts.Password) > 0 {
		conf.Auth = append(conf.Auth, ssh.Password(opts.Password))

		cb := func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			answers = make([]string, len(questions))
			filledCount := 0
			for i, question := range questions {
				challenge := map[string]any{"user": user, "instruction": instruction, "question": question, "echo": echos[i]}
				gologger.Debug().Msgf("SSH keyboard-interactive question %d/%d: %s", i+1, len(questions), vardump.DumpVariables(challenge))
				if !echos[i] && passwordQuestionPattern.MatchString(question) {
					answers[i] = opts.Password
					filledCount++
				} else if echos[i] && usernameQuestionPattern.MatchString(question) {
					answers[i] = opts.User
					filledCount++
				}
			}
			gologger.Debug().Msgf("SSH keyboard-interactive: %d/%d questions filled", filledCount, len(questions))
			return answers, nil
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

	client, err := dialSSH(context.Background(), opts.ExecutionId, fmt.Sprintf("%s:%d", opts.Host, opts.Port), conf)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// dialSSH creates an SSH client over nuclei's policy-aware fastdialer.
func dialSSH(ctx context.Context, executionId, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if !protocolstate.IsHostAllowed(executionId, address) {
		return nil, protocolstate.ErrHostDenied.Msgf(address)
	}
	dialers := protocolstate.GetDialersWithId(executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	conn, err := dialers.Fastdialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if config.Timeout != 0 {
		_ = conn.SetDeadline(time.Now().Add(config.Timeout))
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}
