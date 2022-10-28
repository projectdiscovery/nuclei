package redis

import (
	"fmt"
	"time"

	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	opt := redis.Options{
		Addr:        fmt.Sprintf("%s:%d", host, port),
		Password:    password,
		DB:          0,
		DialTimeout: time.Duration(timeout) * time.Second,
	}
	client := redis.NewClient(&opt)
	defer client.Close()

	_, err := client.Ping().Result()
	if err != nil {
		return false, errors.Wrap(err, "could not connect to redis")
	}
	return true, nil
}
