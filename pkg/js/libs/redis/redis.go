package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	pluginsredis "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/redis/go-redis/v9"
)

// executionIdFromCtx extracts the executionId from the context safely
func executionIdFromCtx(ctx context.Context) (string, error) {
	id, ok := ctx.Value("executionId").(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid executionId in context")
	}
	return id, nil
}

// GetServerInfo returns the server info for a redis server
func GetServerInfo(ctx context.Context, host string, port int) (string, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return "", err
	}
	return memoizedgetServerInfo(ctx, executionId, host, port)
}

// @memo
func getServerInfo(ctx context.Context, executionId string, host string, port int) (string, error) {
	return getServerInfoInternal(ctx, executionId, host, port, "")
}

// Connect tries to connect redis server with password
func Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return false, err
	}
	return memoizedconnect(ctx, executionId, host, port, password)
}

// @memo
func connect(ctx context.Context, executionId string, host string, port int, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	defer client.Close()

	if _, err := client.Ping(ctx).Result(); err != nil {
		return false, err
	}

	return true, nil
}

// GetServerInfoAuth returns the server info for a redis server with password
func GetServerInfoAuth(ctx context.Context, host string, port int, password string) (string, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return "", err
	}
	return memoizedgetServerInfoAuth(ctx, executionId, host, port, password)
}

// @memo
func getServerInfoAuth(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	return getServerInfoInternal(ctx, executionId, host, port, password)
}

// getServerInfoInternal contains common logic for fetching redis info
func getServerInfoInternal(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	defer client.Close()

	if _, err := client.Ping(ctx).Result(); err != nil {
		return "", err
	}

	return client.Info(ctx).Result()
}

// IsAuthenticated checks if the redis server requires authentication
func IsAuthenticated(ctx context.Context, host string, port int) (bool, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return false, err
	}
	return memoizedisAuthenticated(ctx, executionId, host, port)
}

// @memo
func isAuthenticated(ctx context.Context, executionId string, host string, port int) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	plugin := pluginsredis.REDISPlugin{}
	dialer, err := protocolstate.GetDialer()
	if err != nil {
		return false, err
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}

	return service != nil, nil
}

// RunLuaScript runs a lua script on the redis server
func RunLuaScript(ctx context.Context, host string, port int, password string, script string) (interface{}, error) {
	executionId, err := executionIdFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if !protocolstate.IsHostAllowed(executionId, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	defer client.Close()

	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, err
	}

	return client.Eval(ctx, script, []string{}).Result()
}
