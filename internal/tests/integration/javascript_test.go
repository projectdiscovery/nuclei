//go:build integration
// +build integration

package integration_test

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-pg/pg/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/projectdiscovery/utils/reader"
	"go.uber.org/multierr"
)

func javascriptDockerDisabled() bool {
	return !osutils.IsLinux() || !hasAnyExecutable("docker", "podman")
}

var jsTestcases = []integrationCase{
	{Path: "protocols/javascript/redis-pass-brute.yaml", TestCase: &javascriptRedisPassBrute{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/ssh-server-fingerprint.yaml", TestCase: &javascriptSSHServerFingerprint{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/net-multi-step.yaml", TestCase: &networkMultiStep{}},
	{Path: "protocols/javascript/net-https.yaml", TestCase: &javascriptNetHttps{}},
	{Path: "protocols/javascript/rsync-test.yaml", TestCase: &javascriptRsyncTest{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/vnc-pass-brute.yaml", TestCase: &javascriptVncPassBrute{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/postgres-pass-brute.yaml", TestCase: &javascriptPostgresPassBrute{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/mysql-connect.yaml", TestCase: &javascriptMySQLConnect{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/multi-ports.yaml", TestCase: &javascriptMultiPortsSSH{}},
	{Path: "protocols/javascript/no-port-args.yaml", TestCase: &javascriptNoPortArgs{}},
	{Path: "protocols/javascript/telnet-auth-test.yaml", TestCase: &javascriptTelnetAuthTest{}, DisableOn: javascriptDockerDisabled, Serial: true},
	{Path: "protocols/javascript/asrep-roast.yaml", TestCase: &javascriptASRepRoast{}},
	{Path: "protocols/javascript/wmi-command.yaml", TestCase: &javascriptWMICommand{}},
	{Path: "protocols/javascript/goexec-redaction.yaml", TestCase: &javascriptGoExecRedaction{}},
	{Path: "protocols/javascript/goexec-modules.yaml", TestCase: &javascriptGoExecModules{}},
	{Path: "protocols/javascript/goexec-samba-ntlm.yaml", TestCase: &javascriptGoExecSambaNTLM{}, DisableOn: javascriptDockerDisabled, Serial: true},
}

var (
	defaultRetry = 3
)

const (
	javascriptContainerTTLSeconds  = 300
	javascriptDatabaseReadyTimeout = 3 * time.Minute
	javascriptServiceReadyTimeout  = 45 * time.Second
	javascriptRetryDelay           = 500 * time.Millisecond
	javascriptDialTimeout          = 500 * time.Millisecond
)

type javascriptDockerReadyCheck func(address string) error

type javascriptDockerSpec struct {
	options      *dockertest.RunOptions
	port         string
	readyTimeout time.Duration
	settleDelay  time.Duration
	readyCheck   javascriptDockerReadyCheck
}

func newJavascriptDockerSpec(port string, options *dockertest.RunOptions, readyTimeout time.Duration, settleDelay time.Duration, readyCheck javascriptDockerReadyCheck) javascriptDockerSpec {
	if options == nil {
		options = &dockertest.RunOptions{}
	}
	if options.Platform == "" {
		options.Platform = "linux/amd64"
	}
	if len(options.ExposedPorts) == 0 {
		options.ExposedPorts = []string{port}
	}
	if readyTimeout <= 0 {
		readyTimeout = javascriptServiceReadyTimeout
	}
	return javascriptDockerSpec{
		options:      options,
		port:         port,
		readyTimeout: readyTimeout,
		settleDelay:  settleDelay,
		readyCheck:   readyCheck,
	}
}

type javascriptNetHttps struct{}

func (j *javascriptNetHttps) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptRedisPassBrute struct{}

func (j *javascriptRedisPassBrute) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("6379/tcp", &dockertest.RunOptions{
		Repository: "redis",
		Tag:        "latest",
		Cmd:        []string{"redis-server", "--requirepass", "iamadmin"},
	}, javascriptServiceReadyTimeout, 0, nil))
}

type javascriptSSHServerFingerprint struct{}

func (j *javascriptSSHServerFingerprint) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("22/tcp", &dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "latest",
		Cmd: []string{
			"sh",
			"-c",
			"apk add --no-cache openssh && ssh-keygen -A && mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e",
		},
	}, javascriptServiceReadyTimeout, 2*time.Second, nil))
}

type javascriptVncPassBrute struct{}

func (j *javascriptVncPassBrute) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("5900/tcp", &dockertest.RunOptions{
		Repository: "dorowu/ubuntu-desktop-lxde-vnc",
		Tag:        "latest",
		Env: []string{
			"VNC_PASSWORD=mysecret",
		},
	}, javascriptServiceReadyTimeout, 20*time.Second, nil))
}

type javascriptPostgresPassBrute struct{}

func (j *javascriptPostgresPassBrute) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("5432/tcp", &dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "13",
		Env: []string{
			"POSTGRES_INITDB_ARGS=--auth-host=md5 --auth-local=trust",
			"POSTGRES_PASSWORD=postgres",
			"POSTGRES_USER=postgres",
		},
	}, javascriptDatabaseReadyTimeout, 0, postgresReadyCheck("postgres", "postgres")), 1, 2)
}

type javascriptMySQLConnect struct{}

func (j *javascriptMySQLConnect) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("3306/tcp", &dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "5.7",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=secret",
		},
	}, javascriptDatabaseReadyTimeout, 0, mysqlReadyCheck("root", "secret")))
}

type javascriptMultiPortsSSH struct{}

func (j *javascriptMultiPortsSSH) Execute(filePath string) error {
	// use scanme.sh as target to ensure we match on the 2nd default port 22
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptNoPortArgs struct{}

func (j *javascriptNoPortArgs) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "yo.dawg", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptWMICommand struct{}

func (j *javascriptWMICommand) Execute(filePath string) error {
	// Exercises the protocolstate network-policy denial path: the helper sees
	// 203.0.113.10 (RFC 5737 TEST-NET-3, hard-coded inside the template) on
	// the exclude list and short-circuits before any dial, so the JSON result
	// must contain "ok":false plus "network policy" in the error while not
	// leaking the password.
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "127.0.0.1", debug, "-eh", "203.0.113.10")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptGoExecRedaction struct{}

func (j *javascriptGoExecRedaction) Execute(filePath string) error {
	listener := newGoExecCloseListener()
	defer listener.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, listener.host, debug, "-V", "RPCEndpoint="+listener.binding)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptGoExecModules struct{}

func (j *javascriptGoExecModules) Execute(filePath string) error {
	listener := newGoExecCloseListener()
	defer listener.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, listener.host, debug, "-V", "RPCEndpoint="+listener.binding)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptGoExecSambaNTLM struct{}

// Execute spins up a Samba container with a known local user, binds it to
// host 127.0.0.1:445 (the goexec SMB dialer ignores any port carried in the
// target, so a randomised host port would never be reached), and runs the
// SCMR helper against it. NTLM authentication completes end-to-end against a
// real SMB server; the eventual failure happens at the SCMR layer because
// Samba does not implement remote service creation, which is exactly what
// the template asserts (structured Result + redaction).
func (j *javascriptGoExecSambaNTLM) Execute(filePath string) error {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return fmt.Errorf("could not create docker pool: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return fmt.Errorf("could not connect to Docker: %w", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "dperson/samba",
		Tag:          "latest",
		Platform:     "linux/amd64",
		ExposedPorts: []string{"445/tcp"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"445/tcp": {{HostIP: "127.0.0.1", HostPort: "445"}},
		},
		Cmd: []string{
			"-u", "auditor;samba-ntlm-secret",
			"-s", "data;/share;yes;no;no;auditor;auditor;auditor",
			"-w", "WORKGROUP",
			"-p",
		},
	})
	if err != nil {
		return fmt.Errorf("could not start samba: %w", err)
	}
	defer purge(pool, resource)

	if err := resource.Expire(javascriptContainerTTLSeconds); err != nil {
		return fmt.Errorf("could not expire samba: %w", err)
	}

	targetAddress := "127.0.0.1:445"
	if err := waitForTCPService(targetAddress, javascriptServiceReadyTimeout); err != nil {
		return err
	}
	// SMB ready-check: the port binds before smbd is actually accepting
	// negotiate requests (especially under qemu emulation on arm64). Send a
	// minimal SMB2 NEGOTIATE and require the response header to start with
	// 0xFE 'S' 'M' 'B'.
	if err := waitForServiceCheck(targetAddress, javascriptServiceReadyTimeout, smbReadyCheck()); err != nil {
		return err
	}

	errS := make([]error, 0, defaultRetry)
	for attempt := 1; attempt <= defaultRetry; attempt++ {
		results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "127.0.0.1", debug)
		if err == nil {
			if countErr := expectResultsCount(results, 1); countErr == nil {
				return nil
			} else {
				err = countErr
			}
		}
		errS = append(errS, err)
		if attempt < defaultRetry {
			time.Sleep(javascriptRetryDelay)
		}
	}
	return multierr.Combine(errS...)
}

// goExecCloseListener is a loopback TCP listener that accepts incoming
// connections and immediately closes them. It is used to intercept the
// DCERPC dial issued by the GoExec helpers (via Options.Endpoint), so we
// exercise target normalization, host-allowed check, real dial, RPC bind
// failure, structured Result, and redaction without a Windows backend.
type goExecCloseListener struct {
	listener net.Listener
	host     string
	binding  string
}

func newGoExecCloseListener() *goExecCloseListener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Errorf("goexec listener: %w", err))
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		panic(fmt.Errorf("goexec listener addr: %w", err))
	}
	g := &goExecCloseListener{
		listener: ln,
		host:     host,
		binding:  fmt.Sprintf("ncacn_ip_tcp:%s[%s]", host, port),
	}
	go g.serve()
	return g
}

func (g *goExecCloseListener) serve() {
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func (g *goExecCloseListener) Close() {
	_ = g.listener.Close()
}

type javascriptRsyncTest struct{}

func (j *javascriptRsyncTest) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("873/tcp", &dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "latest",
		Cmd:        []string{"sh", "-c", "apk add --no-cache rsync shadow && useradd -m rsyncuser && echo 'rsyncuser:mysecret' | chpasswd && echo 'rsyncuser:MySecret123' > /etc/rsyncd.secrets && chmod 600 /etc/rsyncd.secrets && echo -e '[data]\\n  path = /data\\n  comment = Local Rsync Share\\n  read only = false\\n  auth users = rsyncuser\\n  secrets file = /etc/rsyncd.secrets' > /etc/rsyncd.conf && mkdir -p /data && exec rsync --daemon --no-detach --config=/etc/rsyncd.conf"},
	}, javascriptServiceReadyTimeout, 0, nil))
}

type javascriptTelnetAuthTest struct{}

func (j *javascriptTelnetAuthTest) Execute(filePath string) error {
	return runJavascriptDockerCase(filePath, newJavascriptDockerSpec("23/tcp", &dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "latest",
		Cmd:        []string{"sh", "-c", "apk add --no-cache busybox-extras shadow && useradd -m dev && echo 'dev:mysecret' | chpasswd && exec /usr/sbin/telnetd -F -p 23 -l /bin/login"},
	}, javascriptServiceReadyTimeout, 0, nil))
}

type networkMultiStep struct{}

func (j *networkMultiStep) Execute(filePath string) error {
	errState := &capturedError{}
	server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()

		data, err := reader.ConnReadNWithTimeout(conn, 5, 5*time.Second)
		if err != nil {
			errState.Set(err)
			return
		}
		if string(data) == "FIRST" {
			_, _ = conn.Write([]byte("PING"))
		}

		data, err = reader.ConnReadNWithTimeout(conn, 6, 5*time.Second)
		if err != nil {
			errState.Set(err)
			return
		}
		if string(data) == "SECOND" {
			_, _ = conn.Write([]byte("PONG"))
		}
		_, _ = conn.Write([]byte("NUCLEI"))
	})
	defer server.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, server.URL, debug)
	if err != nil {
		return err
	}
	if err := errState.Err(); err != nil {
		return err
	}
	if debug {
		return expectResultsCount(results, 3)
	}
	return expectResultsCount(results, 1)
}

func runJavascriptDockerCase(filePath string, spec javascriptDockerSpec, expectedNumbers ...int) error {
	if len(expectedNumbers) == 0 {
		expectedNumbers = []int{1}
	}

	if spec.options == nil {
		return fmt.Errorf("missing docker options for %s", filePath)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		return fmt.Errorf("could not create docker pool: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return fmt.Errorf("could not connect to Docker: %w", err)
	}

	resource, err := pool.RunWithOptions(spec.options)
	if err != nil {
		return fmt.Errorf("could not start resource for %s: %w", filePath, err)
	}
	defer purge(pool, resource)

	if err := resource.Expire(javascriptContainerTTLSeconds); err != nil {
		return fmt.Errorf("could not expire resource for %s: %w", filePath, err)
	}

	mappedPort := resource.GetPort(spec.port)
	if mappedPort == "" {
		return fmt.Errorf("missing mapped port for %s", spec.port)
	}

	targetAddress := net.JoinHostPort("127.0.0.1", mappedPort)
	if err := waitForTCPService(targetAddress, spec.readyTimeout); err != nil {
		return err
	}
	if spec.readyCheck != nil {
		if err := waitForServiceCheck(targetAddress, spec.readyTimeout, spec.readyCheck); err != nil {
			return err
		}
	}
	if spec.settleDelay > 0 {
		time.Sleep(spec.settleDelay)
	}

	errS := make([]error, 0, defaultRetry)
	for attempt := 1; attempt <= defaultRetry; attempt++ {
		results, err := testutils.RunNucleiTemplateAndGetResults(filePath, targetAddress, debug)
		if err == nil {
			if countErr := expectResultsCount(results, expectedNumbers...); countErr == nil {
				return nil
			} else {
				err = countErr
			}
		}
		errS = append(errS, err)
		if attempt < defaultRetry {
			time.Sleep(javascriptRetryDelay)
		}
	}

	return multierr.Combine(errS...)
}

func waitForTCPService(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, javascriptDialTimeout)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(javascriptRetryDelay)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out waiting for %s", address)
	}
	return fmt.Errorf("service %s did not become ready: %w", address, lastErr)
}

func waitForServiceCheck(address string, timeout time.Duration, check javascriptDockerReadyCheck) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := check(address); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(javascriptRetryDelay)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out waiting for %s", address)
	}
	return fmt.Errorf("service %s did not become fully ready: %w", address, lastErr)
}

// smbReadyCheck sends a minimal SMB2 NEGOTIATE request and verifies the
// response carries the SMB2 protocol marker (0xFE 'S' 'M' 'B'). This lets us
// wait until samba's smbd is actually answering, not just until the kernel
// has bound port 445.
func smbReadyCheck() javascriptDockerReadyCheck {
	return func(address string) error {
		conn, err := net.DialTimeout("tcp", address, javascriptDialTimeout)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// minimal SMB2 NEGOTIATE: NetBIOS length-prefixed SMB2 header with
		// command=0x0000 (NEGOTIATE) and a 36-byte structure that advertises
		// support for dialect 0x0202 (SMB 2.0.2). Crafted byte-for-byte so we
		// avoid pulling an SMB client library into the test binary.
		req := []byte{
			0x00, 0x00, 0x00, 0x66, // NetBIOS session length = 102 (64 header + 38 negotiate)
			0xfe, 'S', 'M', 'B', // SMB2 protocol marker
			0x40, 0x00, // Structure size
			0x00, 0x00, // Credit charge
			0x00, 0x00, 0x00, 0x00, // Status
			0x00, 0x00, // Command = NEGOTIATE (0)
			0x00, 0x00, // Credits requested
			0x00, 0x00, 0x00, 0x00, // Flags
			0x00, 0x00, 0x00, 0x00, // Next command
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
			0x00, 0x00, 0x00, 0x00, // Reserved
			0x00, 0x00, 0x00, 0x00, // Tree ID
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16 bytes)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x24, 0x00, // NEGOTIATE structure size = 36
			0x01, 0x00, // DialectCount = 1
			0x00, 0x00, // SecurityMode
			0x00, 0x00, // Reserved
			0x00, 0x00, 0x00, 0x00, // Capabilities
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid (16)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
			0x02, 0x02, // Dialect = 0x0202 (SMB 2.0.2)
		}
		if _, err := conn.Write(req); err != nil {
			return err
		}
		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("smb negotiate: read header: %w", err)
		}
		// header[4:8] should be the SMB2 protocol marker (skip the 4-byte NetBIOS prefix)
		if header[4] != 0xFE || header[5] != 'S' || header[6] != 'M' || header[7] != 'B' {
			return fmt.Errorf("smb negotiate: unexpected protocol marker %x", header[4:8])
		}
		return nil
	}
}

func mysqlReadyCheck(username, password string) javascriptDockerReadyCheck {
	return func(address string) error {
		dsn := fmt.Sprintf("%s:%s@tcp(%s)/information_schema?timeout=5s&readTimeout=5s&writeTimeout=5s", username, password, address)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(0)
		return db.Ping()
	}
}

func postgresReadyCheck(username, password string) javascriptDockerReadyCheck {
	return func(address string) error {
		db := pg.Connect(&pg.Options{
			Addr:     address,
			User:     username,
			Password: password,
			Database: "postgres",
		}).WithTimeout(5 * time.Second)
		defer func() { _ = db.Close() }()
		_, err := db.Exec("select 1")
		return err
	}
}

func purge(pool *dockertest.Pool, resource *dockertest.Resource) {
	if resource == nil || pool == nil {
		return
	}
	containerName := resource.Container.Name
	_ = pool.Client.StopContainer(resource.Container.ID, 0)
	_ = pool.Purge(resource)
	_ = pool.RemoveContainerByName(containerName)
}
