package redis

import (
	"fmt"
	"net"
	"time"

	"github.com/go-redis/redis"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	pluginsredis "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
)

// GetServerInfo returns the server info for a redis server
func GetServerInfo(host string, port int) (string, error) {
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Ping the Redis server
	_, err := client.Ping().Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info()
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// Connect tries to connect redis server with password
func Connect(host string, port int, password string) (bool, error) {
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,        // use default DB
	})
	_, err := client.Ping().Result()
	if err != nil {
		return false, err
	}
	// Get Redis server info
	infoCmd := client.Info()
	if infoCmd.Err() != nil {
		return false, infoCmd.Err()
	}

	return true, nil
}


// GetServerInfoAuth returns the server info for a redis server
func GetServerInfoAuth(host string, port int, password string) (string, error) {
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,  // use default DB
	})

	// Ping the Redis server
	_, err := client.Ping().Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info()
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}



// IsAuthenticated checks if the redis server requires authentication
func IsAuthenticated(host string, port int) (bool, error) {
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	_, err = plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	return true, nil
}
