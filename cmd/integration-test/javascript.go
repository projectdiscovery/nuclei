package main

import (
	"log"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	osutils "github.com/projectdiscovery/utils/os"
	"go.uber.org/multierr"
)

var jsTestcases = []TestCaseInfo{
	{Path: "protocols/javascript/redis-pass-brute.yaml", TestCase: &javascriptRedisPassBrute{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/ssh-server-fingerprint.yaml", TestCase: &javascriptSSHServerFingerprint{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/net-multi-step.yaml", TestCase: &networkMultiStep{}},
	{Path: "protocols/javascript/net-https.yaml", TestCase: &javascriptNetHttps{}},
	{Path: "protocols/javascript/rsync-test.yaml", TestCase: &javascriptRsyncTest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/oracle-auth-test.yaml", TestCase: &javascriptOracleAuthTest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/vnc-pass-brute.yaml", TestCase: &javascriptVncPassBrute{}},
	{Path: "protocols/javascript/postgres-pass-brute.yaml", TestCase: &javascriptPostgresPassBrute{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/mysql-connect.yaml", TestCase: &javascriptMySQLConnect{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/multi-ports.yaml", TestCase: &javascriptMultiPortsSSH{}},
	{Path: "protocols/javascript/no-port-args.yaml", TestCase: &javascriptNoPortArgs{}},
	{Path: "protocols/javascript/telnet-auth-test.yaml", TestCase: &javascriptTelnetAuthTest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
}

var (
	redisResource    *dockertest.Resource
	sshResource      *dockertest.Resource
	oracleResource   *dockertest.Resource
	vncResource      *dockertest.Resource
	telnetResource   *dockertest.Resource
	postgresResource *dockertest.Resource
	mysqlResource    *dockertest.Resource
	rsyncResource    *dockertest.Resource
	pool             *dockertest.Pool
	defaultRetry     = 3
)

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
	if redisResource == nil || pool == nil {
		// skip test as redis is not running
		return nil
	}
	tempPort := redisResource.GetPort("6379/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(redisResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let ssh server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptSSHServerFingerprint struct{}

func (j *javascriptSSHServerFingerprint) Execute(filePath string) error {
	if sshResource == nil || pool == nil {
		// skip test as redis is not running
		return nil
	}
	tempPort := sshResource.GetPort("2222/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(sshResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let ssh server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptOracleAuthTest struct{}

func (j *javascriptOracleAuthTest) Execute(filePath string) error {
	if oracleResource == nil || pool == nil {
		// skip test as oracle is not running
		return nil
	}
	tempPort := oracleResource.GetPort("1521/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(oracleResource)

	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			// let oracle server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptVncPassBrute struct{}

func (j *javascriptVncPassBrute) Execute(filePath string) error {
	if vncResource == nil || pool == nil {
		// skip test as vnc is not running
		return nil
	}
	tempPort := vncResource.GetPort("5900/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(vncResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let ssh server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptPostgresPassBrute struct{}

func (j *javascriptPostgresPassBrute) Execute(filePath string) error {
	if postgresResource == nil || pool == nil {
		// skip test as postgres is not running
		return nil
	}
	tempPort := postgresResource.GetPort("5432/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(postgresResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let postgres server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptMySQLConnect struct{}

func (j *javascriptMySQLConnect) Execute(filePath string) error {
	if mysqlResource == nil || pool == nil {
		// skip test as mysql is not running
		return nil
	}
	tempPort := mysqlResource.GetPort("3306/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(mysqlResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let mysql server start
			time.Sleep(5 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
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
	if rsyncResource == nil || pool == nil {
		// skip test as rsync is not running
		return nil
	}
	tempPort := rsyncResource.GetPort("873/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(rsyncResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let rsync server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

type javascriptTelnetAuthTest struct{}

func (j *javascriptTelnetAuthTest) Execute(filePath string) error {
	if telnetResource == nil || pool == nil {
		// skip test as telnet is not running
		return nil
	}
	tempPort := telnetResource.GetPort("23/tcp")
	finalURL := "localhost:" + tempPort
	defer purge(telnetResource)
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			//let telnet server start
			time.Sleep(3 * time.Second)
			results, err = testutils.RunNucleiTemplateAndGetResults(filePath, finalURL, debug)
			return nil
		})
		if err != nil {
			return err
		}
		if err := expectResultsCount(results, 1); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

// purge any given resource if it is not nil
func purge(resource *dockertest.Resource) {
	if resource != nil && pool != nil {
		containerName := resource.Container.Name
		_ = pool.Client.StopContainer(resource.Container.ID, 0)
		err := pool.Purge(resource)
		if err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
		_ = pool.RemoveContainerByName(containerName)
	}
}

func init() {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Printf("something went wrong with dockertest: %s", err)
		return
	}

	// uses pool to try to connect to Docker
	err = pool.Client.Ping()
	if err != nil {
		log.Printf("Could not connect to Docker: %s", err)
	}

	// setup a temporary redis instance
	redisResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "latest",
		Cmd:        []string{"redis-server", "--requirepass", "iamadmin"},
		Platform:   "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := redisResource.Expire(30); err != nil {
		log.Printf("Could not expire resource: %s", err)
	}

	// setup a temporary ssh server
	sshResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "lscr.io/linuxserver/openssh-server",
		Tag:        "latest",
		Env: []string{
			"PUID=1000",
			"PGID=1000",
			"TZ=Etc/UTC",
			"PASSWORD_ACCESS=true",
			"USER_NAME=admin",
			"USER_PASSWORD=admin",
		},
		Platform: "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := sshResource.Expire(30); err != nil {
		log.Printf("Could not expire resource: %s", err)
	}

	// setup a temporary oracle instance
	oracleResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "gvenzl/oracle-xe",
		Tag:        "latest",
		Env: []string{
			"ORACLE_PASSWORD=mysecret",
		},
		Platform: "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start Oracle resource: %s", err)
		return
	}

	// by default expire after 30 sec
	if err := oracleResource.Expire(30); err != nil {
		log.Printf("Could not expire Oracle resource: %s", err)
	}

	// setup a temporary vnc server
	vncResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "dorowu/ubuntu-desktop-lxde-vnc",
		Tag:        "latest",
		Env: []string{
			"VNC_PASSWORD=mysecret",
		},
		Platform: "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := vncResource.Expire(30); err != nil {
		log.Printf("Could not expire resource: %s", err)
	}

	// setup a temporary postgres instance
	postgresResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "latest",
		Env: []string{
			"POSTGRES_PASSWORD=postgres",
			"POSTGRES_USER=postgres",
		},
		Platform: "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start postgres resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := postgresResource.Expire(30); err != nil {
		log.Printf("Could not expire postgres resource: %s", err)
	}

	// setup a temporary mysql instance
	mysqlResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "latest",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=secret",
		},
		Platform: "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start mysql resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := mysqlResource.Expire(30); err != nil {
		log.Printf("Could not expire mysql resource: %s", err)
	}

	// setup a temporary rsync server
	rsyncResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "latest",
		Cmd:        []string{"sh", "-c", "apk add --no-cache rsync shadow && useradd -m rsyncuser && echo 'rsyncuser:mysecret' | chpasswd && echo 'rsyncuser:MySecret123' > /etc/rsyncd.secrets && chmod 600 /etc/rsyncd.secrets && echo -e '[data]\\n  path = /data\\n  comment = Local Rsync Share\\n  read only = false\\n  auth users = rsyncuser\\n  secrets file = /etc/rsyncd.secrets' > /etc/rsyncd.conf && mkdir -p /data && exec rsync --daemon --no-detach --config=/etc/rsyncd.conf"},
		Platform:   "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start Rsync resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := rsyncResource.Expire(30); err != nil {
		log.Printf("Could not expire Rsync resource: %s", err)
	}

	// setup a temporary telnet server
	// username: dev
	// password: mysecret
	telnetResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "latest",
		Cmd:        []string{"sh", "-c", "apk add --no-cache busybox-extras shadow && useradd -m dev && echo 'dev:mysecret' | chpasswd && exec /usr/sbin/telnetd -F -p 23 -l /bin/login"},
		Platform:   "linux/amd64",
	})
	if err != nil {
		log.Printf("Could not start Telnet resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := telnetResource.Expire(30); err != nil {
		log.Printf("Could not expire Telnet resource: %s", err)
	}
}
