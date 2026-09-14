package redis

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/redis/go-redis/v9"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	pluginsredis "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
)

// RedisOptions defines the connection options for a Redis server.
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const opts = new redis.RedisOptions();
// opts.Host = 'acme.com';
// opts.Port = 6379;
// opts.Password = 'password';
// opts.DB = 0;
// opts.Timeout = 10;
// const connected = redis.ConnectWithOptions(opts);
// ```
type RedisOptions struct {
	Host     string // Host is the hostname or IP of the Redis server.
	Port     int    // Port is the Redis port (usually 6379).
	Password string // Password is the Redis AUTH password.
	DB       int    // DB is the Redis database index.
	Timeout  int    // Timeout is the dial/read/write timeout in seconds.
}

// GetServerInfo returns the server info for a redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfo('acme.com', 6379);
// ```
func GetServerInfo(ctx context.Context, host string, port int) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfo(ctx, executionId, host, port)
}

// @memo
func getServerInfo(ctx context.Context, executionId string, host string, port int) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(redisClientOptions(executionId, RedisOptions{Host: host, Port: port}))
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// Connect tries to connect redis server with password.
//
// Deprecated: prefer ConnectWithOptions for new templates.
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const connected = redis.Connect('acme.com', 6379, 'password');
// ```
func Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(ctx, executionId, host, port, password)
}

// ConnectWithOptions tries to connect to Redis using the supplied options.
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const opts = new redis.RedisOptions();
// opts.Host = 'acme.com';
// opts.Port = 6379;
// opts.Password = 'password';
// opts.DB = 1;
// const connected = redis.ConnectWithOptions(opts);
// ```
func ConnectWithOptions(ctx context.Context, opts RedisOptions) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return connectWithOptions(ctx, executionId, opts)
}

// @memo
func connect(ctx context.Context, executionId string, host string, port int, password string) (bool, error) {
	return connectWithOptions(ctx, executionId, RedisOptions{Host: host, Port: port, Password: password})
}

func connectWithOptions(ctx context.Context, executionId string, opts RedisOptions) (bool, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}
	// create a new client
	client := redis.NewClient(redisClientOptions(executionId, opts))
	defer func() {
		_ = client.Close()
	}()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return false, err
	}
	// Get Redis server info
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return false, infoCmd.Err()
	}

	return true, nil
}

func redisClientOptions(executionId string, opts RedisOptions) *redis.Options {
	clientOpts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", opts.Host, opts.Port),
		Password: opts.Password,
		DB:       opts.DB,
		Dialer:   redisDialer(executionId),
	}
	if opts.Timeout > 0 {
		timeout := time.Duration(opts.Timeout) * time.Second
		clientOpts.DialTimeout = timeout
		clientOpts.ReadTimeout = timeout
		clientOpts.WriteTimeout = timeout
	}
	return clientOpts
}

func redisDialer(executionId string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if !protocolstate.IsHostAllowed(executionId, address) {
			return nil, protocolstate.ErrHostDenied.Msgf(address)
		}
		dialers := protocolstate.GetDialersWithId(executionId)
		if dialers == nil {
			return nil, fmt.Errorf("dialers not initialized for %s", executionId)
		}
		return dialers.Fastdialer.Dial(ctx, network, address)
	}
}

// GetServerInfoAuth returns the server info for a redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
// ```
func GetServerInfoAuth(ctx context.Context, host string, port int, password string) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfoAuth(ctx, executionId, host, port, password)
}

// @memo
func getServerInfoAuth(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := redis.NewClient(redisClientOptions(executionId, RedisOptions{Host: host, Port: port, Password: password}))
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(ctx)
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
	return memoizedisAuthenticated(ctx, executionId, host, port)
}

// @memo
func isAuthenticated(ctx context.Context, executionId string, host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
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
	client := redis.NewClient(redisClientOptions(executionId, RedisOptions{Host: host, Port: port, Password: password}))
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
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
		case string:
			// the goja runtime zero-fills omitted trailing JS arguments with
			// the previous parameter's type, so a 4-arg call (old signature)
			// delivers "" here: treat it as no keys (backwards compat)
			if v != "" {
				return nil, fmt.Errorf("keys must be []string or []interface{}, got string")
			}
		default:
			return nil, fmt.Errorf("keys must be []string or []interface{}, got %T", keys)
		}
	}

	// Convert interface{} args to []interface{} for Eval (handle backwards
	// compatibility). Non-string items (numbers, booleans from JavaScript)
	// are stringified rather than dropped: Redis ARGV values are always
	// bulk strings on the Lua side, so "123"/"true" match JS expectations.
	argsInterface := []interface{}{}
	if args != nil {
		switch v := args.(type) {
		case []string:
			argsInterface = make([]interface{}, len(v))
			for i, arg := range v {
				argsInterface[i] = arg
			}
		case []interface{}:
			argsInterface = make([]interface{}, len(v))
			for i, item := range v {
				argsInterface[i] = fmt.Sprintf("%v", item)
			}
		case string:
			// zero-value padding from omitted JS arguments (see keys above)
			if v != "" {
				return nil, fmt.Errorf("args must be []string or []interface{}, got string")
			}
		default:
			return nil, fmt.Errorf("args must be []string or []interface{}, got %T", args)
		}
	}

	// Execute the Lua script with keys and args
	infoCmd := client.Eval(ctx, script, keysSlice, argsInterface...)

	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}
