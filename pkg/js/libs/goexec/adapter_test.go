package goexec

import (
	"bytes"
	"context"
	"strings"
	"testing"

	upstream "github.com/FalconOpsLLC/goexec/pkg/goexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestRunRedactsRunnerErrors(t *testing.T) {
	restore := SetRunnerForTesting(runnerFunc(func(context.Context, Request) (*Result, error) {
		return nil, assertErr("authentication failed with secret-pass")
	}))
	defer restore()

	result := Run(context.Background(), Request{
		Module:  "wmi",
		Method:  "command",
		Target:  "127.0.0.1",
		Auth:    Password("CORP\\auditor", "secret-pass"),
		Command: "whoami",
		Options: DefaultExecutionOptions(),
	})
	if result.OK {
		t.Fatal("expected failed result")
	}
	if strings.Contains(result.Error, "secret-pass") {
		t.Fatalf("secret leaked in result error: %q", result.Error)
	}
}

func TestGoExecRunnerDeniesNetworkPolicyBeforeDial(t *testing.T) {
	executionID := "goexec-deny-test"
	if err := protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{"denied.local"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := WithExecutionID(context.Background(), executionID)

	result := Run(ctx, Request{
		Module:  "wmi",
		Method:  "command",
		Target:  "denied.local",
		Auth:    Password("CORP\\auditor", "secret"),
		Command: "whoami",
		Options: DefaultExecutionOptions(),
	})
	if result.OK || !strings.Contains(result.Error, "network policy") {
		t.Fatalf("expected network-policy denial result, got %#v", result)
	}
}

func TestGoExecRunnerDeniesProxyNetworkPolicyBeforeDial(t *testing.T) {
	executionID := "goexec-proxy-deny-test"
	if err := protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{"169.254.169.254"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := WithExecutionID(context.Background(), executionID)

	options := DefaultExecutionOptions()
	options.Proxy = "socks5://169.254.169.254:1080"
	result := Run(ctx, Request{
		Module:  "wmi",
		Method:  "command",
		Target:  "127.0.0.1",
		Auth:    Password("CORP\\auditor", "secret"),
		Command: "whoami",
		Options: options,
	})
	if result.OK || !strings.Contains(result.Error, ErrProxyDenied.Error()) {
		t.Fatalf("expected proxy network-policy denial result, got %#v", result)
	}
}

func TestGoExecRunnerDeniesEndpointNetworkPolicyBeforeDial(t *testing.T) {
	executionID := "goexec-endpoint-deny-test"
	if err := protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{"169.254.169.254"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocolstate.Close(executionID) })
	ctx := WithExecutionID(context.Background(), executionID)

	options := DefaultExecutionOptions()
	options.Endpoint = "ncacn_ip_tcp:169.254.169.254[135]"
	result := Run(ctx, Request{
		Module:  "wmi",
		Method:  "command",
		Target:  "127.0.0.1",
		Auth:    Password("CORP\\auditor", "secret"),
		Command: "whoami",
		Options: options,
	})
	if result.OK || !strings.Contains(result.Error, ErrEndpointDenied.Error()) {
		t.Fatalf("expected endpoint network-policy denial result, got %#v", result)
	}
}

func TestCollectExecutionOutputCopiesWriter(t *testing.T) {
	var out bytes.Buffer
	_, _ = out.WriteString("captured output")

	req := Request{Options: DefaultExecutionOptions()}
	req.Options.Output = true
	result := newResult(req)
	execIO := &upstream.ExecutionIO{
		Output: &upstream.ExecutionOutput{
			Writer: nopWriteCloser{Writer: &out},
		},
	}

	collectExecutionOutput(req, result, execIO)

	if result.Stdout != "captured output" || !result.OutputCollected {
		t.Fatalf("expected collected output in result, got %#v", result)
	}
}

type runnerFunc func(context.Context, Request) (*Result, error)

func (f runnerFunc) Run(ctx context.Context, req Request) (*Result, error) {
	return f(ctx, req)
}

type assertErr string

func (a assertErr) Error() string { return string(a) }
