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
	SSHClient struct {
		connection *ssh.Client
		timeout    time.Duration
	}
)

var (
	passwordQuestionPattern = regexp.MustCompile(`(?i)(pass(word|phrase|code)?|pin)`)
	usernameQuestionPattern = regexp.MustCompile(`(?i)(user(name)?|login)`)
)

func (c *SSHClient) SetTimeout(sec int) {
	c.timeout = time.Duration(sec) * time.Second
}

func (c *SSHClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	conn, err := connect(ctx, &connectOptions{
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

func (c *SSHClient) ConnectWithKey(ctx context.Context, host string, port int, username, key string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປ
	conn, err := connect(ctx, &connectOptions{
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

func (c *SSHClient) ConnectSSHInfoMode(ctx context.Context, host string, port int) (*ssh.HandshakeLog, error) {
	executionId := ctx.Value("executionId").(string)
	// ແກ້ໄຂ: ສົ່ງ ctx ຕໍ່ໄປຫາ memoizedconnectSSHInfoMode
	return memoizedconnectSSHInfoMode(ctx, &connectOptions{
		Host:        host,
		Port:        port,
		ExecutionId: executionId,
	})
}

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

func (c *SSHClient) Close() (bool, error) {
	if err := c.connection.Close(); err != nil {
		return false, err
	}
	return true, nil
}

type connectOptions struct {
	Host        string
	Port        int
	User        string
	Password    string
	PrivateKey  string
	Timeout     time.Duration
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
		return protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	return nil
}

// @memo
// ແກ້ໄຂ: ເພີ່ມ ctx ເຂົ້າໄປໃນພາຣາມິເຕີ
func connectSSHInfoMode(ctx context.Context, opts *connectOptions) (*ssh.HandshakeLog, error) {
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
	
	// ແກ້ໄຂ: ປ່ຽນຈາກການໃຊ້ Dial ແບບທຳມະດາ ເປັນການໃຊ້ dialer ຈາກ protocolstate ເພື່ອຮອງຮັບ context
	dialer := protocolstate.GetDialersWithId(opts.ExecutionId)
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", opts.ExecutionId)
	}
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", rhost)
	if err != nil {
		return nil, err
	}
	
	client, err := ssh.NewClient(conn, sshConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = client.Close()
	}()

	return data, nil
}

// ແກ້ໄຂ: ເພີ່ມ ctx ເຂົ້າໄປໃນພາຣາມິເຕີ
func connect(ctx context.Context, opts *connectOptions) (*ssh.Client, error) {
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

	// ແກ້ໄຂ: ປ່ຽນມາໃຊ້ Fastdialer ກັບ context
	dialer := protocolstate.GetDialersWithId(opts.ExecutionId)
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", opts.ExecutionId)
	}
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port))
	if err != nil {
		return nil, err
	}

	client, err := ssh.NewClient(conn, conf)
	if err != nil {
		return nil, err
	}
	return client, nil
}
