package grpc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const healthMethod = "grpc.health.v1.Health/Check"

// startHealthServer starts an in-process gRPC server exposing the standard
// health service (status SERVING) and server reflection, listening on a random
// loopback port. It returns the "host:port" address.
func startHealthServer(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	reflection.Register(srv)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return lis.Addr().String()
}

// initExec initializes protocolstate for a unique executionId derived from the
// test name and registers cleanup. It returns the executionId.
func initExec(t *testing.T, options *types.Options) string {
	t.Helper()

	executionID := "grpc-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	options.ExecutionId = executionID
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	return executionID
}

// newRuntimeClient constructs a *Client through the goja runtime exactly as a
// nuclei template would, wiring the executionId and ctx context values.
func newRuntimeClient(t *testing.T, executionID, target string, opts Options) (*Client, error) {
	t.Helper()

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", context.Background())

	obj, err := runtime.New(runtime.ToValue(NewClient), runtime.ToValue(target), runtime.ToValue(opts))
	if err != nil {
		return nil, err
	}
	client, ok := obj.Export().(*Client)
	require.True(t, ok, "expected *Client export, got %T", obj.Export())
	t.Cleanup(func() { client.Close() })
	return client, nil
}

// healthProtoset builds a serialized FileDescriptorSet covering the health
// service (and its transitive imports).
func healthProtoset(t *testing.T) []byte {
	t.Helper()

	fds := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imports := fd.Imports()
		for i := 0; i < imports.Len(); i++ {
			add(imports.Get(i).FileDescriptor)
		}
		fds.File = append(fds.File, protodesc.ToFileDescriptorProto(fd))
	}
	add(healthpb.File_grpc_health_v1_health_proto)

	data, err := proto.Marshal(fds)
	require.NoError(t, err)
	return data
}

func setTemplateDir(t *testing.T) string {
	t.Helper()
	templatesDir := t.TempDir()
	original := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(original) })
	return templatesDir
}

func TestInvokeHealthCheckViaReflection(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.Invoke(healthMethod, `{"service":""}`)
	require.Contains(t, resp, "SERVING")
}

func TestInvokeWithEmptyMessageDefaultsToObject(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.Invoke(healthMethod, "")
	require.Contains(t, resp, "SERVING")
}

func TestInvokeWithHeaders(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.InvokeWithHeaders(healthMethod, `{}`, []string{"x-custom: nuclei"})
	require.Contains(t, resp, "SERVING")
}

func TestListServicesAndMethodsViaReflection(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	services := client.ListServices()
	require.Contains(t, services, "grpc.health.v1.Health")

	methods := client.ListMethods("grpc.health.v1.Health")
	require.Contains(t, methods, "grpc.health.v1.Health.Check")
}

func TestDescribeSymbol(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	text := client.DescribeSymbol("grpc.health.v1.Health")
	require.Contains(t, text, "Health")
	require.Contains(t, text, "Check")
}

func TestInvokeViaProtosetInsideTemplatesDir(t *testing.T) {
	addr := startHealthServer(t)
	templatesDir := setTemplateDir(t)
	// local file access disabled: the protoset must be resolved from inside the
	// templates directory by the allowlist.
	executionID := initExec(t, &types.Options{AllowLocalFileAccess: false})

	protosetPath := filepath.Join(templatesDir, "health.protoset")
	require.NoError(t, os.WriteFile(protosetPath, healthProtoset(t), 0o600))

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true, ProtosetFile: protosetPath})
	require.NoError(t, err)

	resp := client.Invoke(healthMethod, `{"service":""}`)
	require.Contains(t, resp, "SERVING")
}

func TestProtosetOutsideTemplatesDirDenied(t *testing.T) {
	setTemplateDir(t)
	executionID := initExec(t, &types.Options{AllowLocalFileAccess: false})

	// write the protoset outside the templates directory
	outside := filepath.Join(t.TempDir(), "health.protoset")
	require.NoError(t, os.WriteFile(outside, healthProtoset(t), 0o600))

	_, _, err := descriptorSource(context.Background(), executionID, nil, outside)
	require.Error(t, err)
	require.Contains(t, err.Error(), "protoset path denied")
}

func TestConstructorDeniesHostByNetworkPolicy(t *testing.T) {
	executionID := initExec(t, &types.Options{ExcludeTargets: []string{"127.0.0.1"}})

	_, err := newRuntimeClient(t, executionID, "127.0.0.1:9", Options{Plaintext: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "network policy")
}

func TestDialTargetRejectsDeniedHost(t *testing.T) {
	executionID := initExec(t, &types.Options{ExcludeTargets: []string{"127.0.0.1"}})

	_, err := dialTarget(context.Background(), executionID, "127.0.0.1:9", connConfig{plaintext: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "network policy")
}

func TestDialTargetRejectsInvalidTarget(t *testing.T) {
	executionID := initExec(t, &types.Options{})

	_, err := dialTarget(context.Background(), executionID, "missing-port", connConfig{plaintext: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "host:port")
}

func TestDialTargetRejectsEmptyExecutionID(t *testing.T) {
	_, err := dialTarget(context.Background(), "", "127.0.0.1:9", connConfig{plaintext: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "executionId")
}

func TestInvokeUnaryEndToEndWithHelpers(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	cc, err := dialTarget(context.Background(), executionID, addr, connConfig{plaintext: true})
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	src, cleanup, err := descriptorSource(context.Background(), executionID, cc, "")
	require.NoError(t, err)
	defer cleanup()

	resp, err := invokeUnary(context.Background(), src, cc, healthMethod, `{"service":""}`, nil)
	require.NoError(t, err)
	require.Contains(t, resp, "SERVING")
}

func TestInvokeUnaryUnknownMethod(t *testing.T) {
	addr := startHealthServer(t)
	executionID := initExec(t, &types.Options{})

	cc, err := dialTarget(context.Background(), executionID, addr, connConfig{plaintext: true})
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	src, cleanup, err := descriptorSource(context.Background(), executionID, cc, "")
	require.NoError(t, err)
	defer cleanup()

	_, err = invokeUnary(context.Background(), src, cc, "grpc.health.v1.Health/DoesNotExist", `{}`, nil)
	require.Error(t, err)
}
