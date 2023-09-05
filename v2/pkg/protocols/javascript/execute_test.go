package javascript_test

import (
	"log"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
)

func TestMain(m *testing.M) {
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

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
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
	})
	if err != nil {
		log.Printf("Could not start resource: %s", err)
		return
	}
	// by default expire after 30 sec
	if err := resource.Expire(60); err != nil {
		log.Printf("Could not expire resource: %s", err)
	}
	defer func() {
		err = pool.Purge(resource)
		if err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
	}()
	log.Printf("running ssh-server on port %s", resource.GetPort("2222/tcp"))

	time.Sleep(time.Duration(60) * time.Second)

}
