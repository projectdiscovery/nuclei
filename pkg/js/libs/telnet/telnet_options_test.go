package telnet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestTelnetTimeout(t *testing.T) {
	if got := telnetTimeout(2); got != 2*time.Second {
		t.Fatalf("timeout = %s, want 2s", got)
	}
	if got := telnetTimeout(0); got != 10*time.Second {
		t.Fatalf("default timeout = %s, want 10s", got)
	}
}

func TestConnectWithOptionsValidatesTarget(t *testing.T) {
	connected, err := (&TelnetClient{}).ConnectWithOptions(context.Background(), TelnetOptions{Port: 23})
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

	ctx := context.WithValue(context.Background(), "executionId", executionID) // nolint:staticcheck
	connected, err := (&TelnetClient{}).ConnectWithOptions(ctx, TelnetOptions{
		Host: "127.0.0.1", Port: 23, Timeout: 1,
	})
	if connected || err == nil || !strings.Contains(err.Error(), "network policy") {
		t.Fatalf("expected network-policy denial before dialing, got connected=%t err=%v", connected, err)
	}
}
