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

func GetServerInfo(ctx context.Context, host string, port int) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfo(ctx, executionId, host, port) // ສົ່ງ ctx ຕໍ່ໄປ
}

// @memo
func getServerInfo(ctx context.Context, executionId string, host string, port int) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: "", 
		DB:       0,  
	})
	defer func() {
		_ = client.Close()
	}()

	// ປ່ຽນຈາກ context.TODO() ເປັນ ctx
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

func Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(ctx, executionId, host, port, password)
}

// @memo
func connect(ctx context.Context, executionId string, host string, port int, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, 
		DB:       0,        
	})
	defer func() {
		_ = client.Close()
	}()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return false, err
	}
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return false, infoCmd.Err()
	}

	return true, nil
}

func GetServerInfoAuth(ctx context.Context, host string, port int, password string) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfoAuth(ctx, executionId, host, port, password)
}

// @memo
func getServerInfoAuth(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, 
		DB:       0,        
	})
	defer func() {
		_ = client.Close()
	}()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

func IsAuthenticated(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisAuthenticated(ctx, executionId, host, port)
}

// @memo
func isAuthenticated(ctx context.Context, executionId string, host string, port int) (bool, error) {
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	// ປ່ຽນຈາກ context.TODO() ເປັນ ctx
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

func RunLuaScript(ctx context.Context, host string, port int, password string, script string) (interface{}, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		DB:       0, 
	})
	defer func() {
		_ = client.Close()
	}()

	// ປ່ຽນທັງໝົດເປັນ ctx
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	infoCmd := client.Eval(ctx, script, []string{})

	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}
