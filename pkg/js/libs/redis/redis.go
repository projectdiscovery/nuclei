package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/redis/go-redis/v9"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	pluginsredis "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
)

// GetServerInfo returns the server info for a redis server
func GetServerInfo(host string, port int) (string, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Ping the Redis server
	_, err := client.Ping(context.TODO()).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(context.TODO())
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// Connect tries to connect redis server with password
func Connect(host string, port int, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,        // use default DB
	})
	_, err := client.Ping(context.TODO()).Result()
	if err != nil {
		return false, err
	}
	// Get Redis server info
	infoCmd := client.Info(context.TODO())
	if infoCmd.Err() != nil {
		return false, infoCmd.Err()
	}

	return true, nil
}

// GetServerInfoAuth returns the server info for a redis server
func GetServerInfoAuth(host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,        // use default DB
	})

	// Ping the Redis server
	_, err := client.Ping(context.TODO()).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(context.TODO())
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// IsAuthenticated checks if the redis server requires authentication
func IsAuthenticated(host string, port int) (bool, error) {
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
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

// RunLuaScript runs a lua script on
func RunLuaScript(host string, port int, password string, script string) (interface{}, error) {
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		DB:       0, // use default DB
	})

	// Ping the Redis server
	_, err := client.Ping(context.TODO()).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Eval(context.Background(), script, []string{})

	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}
