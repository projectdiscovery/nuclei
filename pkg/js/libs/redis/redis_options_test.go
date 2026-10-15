package redis

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestRedisClientOptionsMapsConnectionOptions(t *testing.T) {
	opts := redisClientOptions("test", RedisOptions{
		Host: "127.0.0.1", Port: 6379, Password: "secret", DB: 3, Timeout: 4,
	})

	if opts.Addr != "127.0.0.1:6379" || opts.Password != "secret" || opts.DB != 3 {
		t.Fatalf("unexpected Redis client options: %#v", opts)
	}
	if opts.DialTimeout != 4*time.Second || opts.ReadTimeout != 4*time.Second || opts.WriteTimeout != 4*time.Second {
		t.Fatalf("timeout mapping failed: %#v", opts)
	}
}

func TestConnectWithOptionsValidatesTarget(t *testing.T) {
	connected, err := connectWithOptions(context.Background(), "test", RedisOptions{Port: 6379})
	if connected || err == nil || err.Error() != "invalid host or port" {
		t.Fatalf("expected invalid target error, got connected=%t err=%v", connected, err)
	}
}

func TestConnectWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	if err := protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocolstate.Close(executionID) })

	connected, err := connectWithOptions(context.Background(), executionID, RedisOptions{
		Host: "127.0.0.1", Port: 6379, Timeout: 1,
	})
	if connected || err == nil || !strings.Contains(err.Error(), "network policy") {
		t.Fatalf("expected network-policy denial before dialing, got connected=%t err=%v", connected, err)
	}
}
