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
	{Path: "protocols/javascript/redis-lua-script.yaml", TestCase: &javascriptRedisLuaScript{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/ssh-server-fingerprint.yaml", TestCase: &javascriptSSHServerFingerprint{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/net-multi-step.yaml", TestCase: &networkMultiStep{}},
	{Path: "protocols/javascript/net-https.yaml", TestCase: &javascriptNetHttps{}},
	{Path: "protocols/javascript/oracle-auth-test.yaml", TestCase: &javascriptOracleAuthTest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/javascript/vnc-pass-brute.yaml", TestCase: &javascriptVncPassBrute{}},
	{Path: "protocols/javascript/multi-ports.yaml", TestCase: &javascriptMultiPortsSSH{}},
}

var (
	redisResource  *dockertest.Resource
	sshResource    *dockertest.Resource
	oracleResource *dockertest.Resource
	vncResource    *dockertest.Resource
	pool           *dockertest.Pool
	defaultRetry   = 3
)

type javascriptNetHttps struct{}

func (j *javascriptNetHttps) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// executeDockerJSTest runs a nuclei template against a dockerized service,
// retrying a few times to accommodate service startup. When purgeAfter is
// true the container is purged once the test finishes; tests sharing a
// resource must only purge on the last test using it.
func executeDockerJSTest(filePath string, resource *dockertest.Resource, port string, purgeAfter bool) error {
	if resource == nil || pool == nil {
		// skip test as the service is not running
		return nil
	}
	tempPort := resource.GetPort(port)
	finalURL := "localhost:" + tempPort
	if purgeAfter {
		defer purge(resource)
	}
	errs := []error{}
	for i := 0; i < defaultRetry; i++ {
		results := []string{}
		var err error
		_ = pool.Retry(func() error {
			// let the service start
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

type javascriptRedisPassBrute struct{}

func (j *javascriptRedisPassBrute) Execute(filePath string) error {
	// do not purge: the redis container is shared with javascriptRedisLuaScript
	return executeDockerJSTest(filePath, redisResource, "6379/tcp", false)
}

type javascriptRedisLuaScript struct{}

func (j *javascriptRedisLuaScript) Execute(filePath string) error {
	// last test using the redis container: purge it once done
	return executeDockerJSTest(filePath, redisResource, "6379/tcp", true)
}

type javascriptSSHServerFingerprint struct{}

func (j *javascriptSSHServerFingerprint) Execute(filePath string) error {
	return executeDockerJSTest(filePath, sshResource, "2222/tcp", true)
}

type javascriptOracleAuthTest struct{}

func (j *javascriptOracleAuthTest) Execute(filePath string) error {
	return executeDockerJSTest(filePath, oracleResource, "1521/tcp", true)
}

type javascriptVncPassBrute struct{}

func (j *javascriptVncPassBrute) Execute(filePath string) error {
	return executeDockerJSTest(filePath, vncResource, "5900/tcp", true)
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
	// the redis container is shared by two sequential testcases (pass-brute
	// and lua-script), so give it a longer hard-kill window; the last test
	// purges it explicitly anyway
	if err := redisResource.Expire(180); err != nil {
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
}
