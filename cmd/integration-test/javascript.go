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
}

var (
	redisResource *dockertest.Resource
	sshResource   *dockertest.Resource
	rsyncResource *dockertest.Resource
	pool          *dockertest.Pool
	defaultRetry  = 3
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

}
