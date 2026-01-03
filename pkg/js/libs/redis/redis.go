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
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfo('acme.com', 6379);
// ```
func GetServerInfo(ctx context.Context, host string, port int) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfo(executionId, host, port)
}

// @memo
func getServerInfo(executionId string, host string, port int) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer func() {
		_ = client.Close()
	}()

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
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const connected = redis.Connect('acme.com', 6379, 'password');
// ```
func Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(executionId, host, port, password)
}

// @memo
func connect(executionId string, host string, port int, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,        // use default DB
	})
	defer func() {
		_ = client.Close()
	}()

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
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
// ```
func GetServerInfoAuth(ctx context.Context, host string, port int, password string) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfoAuth(executionId, host, port, password)
}

// @memo
func getServerInfoAuth(executionId string, host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       0,        // use default DB
	})
	defer func() {
		_ = client.Close()
	}()

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
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);
// ```
func IsAuthenticated(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisAuthenticated(executionId, host, port)
}

// @memo
func isAuthenticated(executionId string, host string, port int) (bool, error) {
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	return true, nil
}

// RunLuaScript runs a lua script on the redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// // Old signature (backwards compatible) - keys and args are optional
// const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("ping")');
// // New signature with keys and args
// const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])', ['mykey'], []);
// ```
func RunLuaScript(ctx context.Context, host string, port int, password string, script string, keys interface{}, args interface{}) (interface{}, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		DB:       0, // use default DB
	})
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(context.TODO()).Result()
	if err != nil {
		return "", err
	}

	// Convert interface{} to []string for keys (handle backwards compatibility)
	keysSlice := []string{}
	if keys != nil {
		switch v := keys.(type) {
		case []string:
			keysSlice = v
		case []interface{}:
			keysSlice = make([]string, 0, len(v))
			for _, item := range v {
				keysSlice = append(keysSlice, fmt.Sprintf("%v", item))
			}
		}
	}

	// Convert interface{} to []string for args (handle backwards compatibility)
	argsSlice := []string{}
	if args != nil {
		switch v := args.(type) {
		case []string:
			argsSlice = v
		case []interface{}:
			// Convert []interface{} to []string (from JavaScript arrays)
			argsSlice = make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					argsSlice = append(argsSlice, s)
				}
			}
		}
	}

	// Convert []string args to []interface{} for Eval
	argsInterface := make([]interface{}, len(argsSlice))
	for i, arg := range argsSlice {
		argsInterface[i] = arg
	}

	// Execute the Lua script with keys and args
	infoCmd := client.Eval(context.Background(), script, keysSlice, argsInterface...)

	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}
