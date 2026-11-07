package compiler

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// TestGRPCModuleRequire proves the nuclei/grpc native module is registered in
// the runtime pool and reachable end to end from a JS template via require().
func TestGRPCModuleRequire(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	reflection.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	executionID := "grpc-require-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	script := fmt.Sprintf(`
		const grpc = require('nuclei/grpc');
		const opts = new grpc.Options();
		opts.Plaintext = true;
		const client = new grpc.Client(%q, opts);
		const resp = client.Invoke('grpc.health.v1.Health/Check', '{"service":""}');
		client.Close();
		ExportAs('resp', resp);
		true;
	`, lis.Addr().String())

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)

	result, err := New().ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: executionID,
		Source:      &script,
		TimeoutVariants: &types.Timeouts{
			JsCompilerExecutionTimeout: 10 * time.Second,
		},
	})
	require.NoError(t, err)
	require.Contains(t, fmt.Sprint(result["resp"]), "SERVING")
}
