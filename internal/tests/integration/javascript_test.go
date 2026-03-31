//go:build integration
// +build integration

package integration_test

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/go-pg/pg/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/ory/dockertest/v3"
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
