package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	grpc_testing "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const (
	unaryMethod     = "grpc.testing.TestService/UnaryCall"
	emptyMethod     = "grpc.testing.TestService/EmptyCall"
	streamingMethod = "grpc.testing.TestService/StreamingOutputCall"
)

// interopTestService implements a handful of the standard grpc.testing
// TestService methods, exercising rich field types (enums, nested messages,
// bytes), request metadata, error status propagation and server streaming.
type interopTestService struct {
	grpc_testing.UnimplementedTestServiceServer
}

func (s *interopTestService) EmptyCall(_ context.Context, _ *grpc_testing.Empty) (*grpc_testing.Empty, error) {
	return &grpc_testing.Empty{}, nil
}

func (s *interopTestService) UnaryCall(ctx context.Context, req *grpc_testing.SimpleRequest) (*grpc_testing.SimpleResponse, error) {
	if st := req.GetResponseStatus(); st != nil && st.GetCode() != 0 {
		return nil, status.Error(codes.Code(st.GetCode()), st.GetMessage())
	}
	resp := &grpc_testing.SimpleResponse{
		Payload: &grpc_testing.Payload{
			Type: req.GetResponseType(),
			Body: make([]byte, req.GetResponseSize()),
		},
	}
	if req.GetFillUsername() {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get("x-username"); len(v) > 0 {
				resp.Username = v[0]
			}
		}
	}
	if req.GetFillOauthScope() {
		resp.OauthScope = "test-scope"
	}
	return resp, nil
}

func (s *interopTestService) StreamingOutputCall(req *grpc_testing.StreamingOutputCallRequest, stream grpc.ServerStreamingServer[grpc_testing.StreamingOutputCallResponse]) error {
	for _, p := range req.GetResponseParameters() {
		if err := stream.Send(&grpc_testing.StreamingOutputCallResponse{
			Payload: &grpc_testing.Payload{Type: req.GetResponseType(), Body: make([]byte, p.GetSize())},
		}); err != nil {
			return err
		}
	}
	return nil
}

// startTestService starts an in-process TestService with reflection enabled and
// returns its "host:port" address. If cert is non-nil the server uses TLS.
func startTestService(t *testing.T, cert *tls.Certificate) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var opts []grpc.ServerOption
	if cert != nil {
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(cert)))
	}
	srv := grpc.NewServer(opts...)
	grpc_testing.RegisterTestServiceServer(srv, &interopTestService{})
	// also register health so TLS test can reuse it if needed
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	reflection.Register(srv)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// marshalDescriptorSet serializes a FileDescriptorSet covering fd and all of
// its transitive imports.
func marshalDescriptorSet(t *testing.T, fd protoreflect.FileDescriptor) []byte {
	t.Helper()
	fds := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var add func(f protoreflect.FileDescriptor)
	add = func(f protoreflect.FileDescriptor) {
		if seen[f.Path()] {
			return
		}
		seen[f.Path()] = true
		imports := f.Imports()
		for i := 0; i < imports.Len(); i++ {
			add(imports.Get(i).FileDescriptor)
		}
		fds.File = append(fds.File, protodesc.ToFileDescriptorProto(f))
	}
	add(fd)
	data, err := proto.Marshal(fds)
	require.NoError(t, err)
	return data
}

func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func TestEmptyCall(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.Invoke(emptyMethod, "{}")
	require.Equal(t, "{}", resp)
}

func TestUnaryCallEchoesPayloadAndScope(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.Invoke(unaryMethod, `{"responseSize": 4, "fillOauthScope": true}`)
	require.Contains(t, resp, "test-scope")
	require.Contains(t, resp, "payload")
	// 4 zero bytes base64-encoded
	require.Contains(t, resp, "AAAAAA==")
}

func TestUnaryCallWithMetadataUsername(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.InvokeWithHeaders(unaryMethod, `{"fillUsername": true}`, []string{"x-username: nuclei-user"})
	require.Contains(t, resp, "nuclei-user")
}

func TestUnaryCallPropagatesErrorStatus(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	cc, err := dialTarget(context.Background(), executionID, addr, connConfig{plaintext: true})
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	src, cleanup, err := descriptorSource(context.Background(), executionID, cc, "")
	require.NoError(t, err)
	defer cleanup()

	_, err = invokeUnary(context.Background(), src, cc, unaryMethod, `{"responseStatus": {"code": 5, "message": "boom"}}`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NotFound")
	require.Contains(t, err.Error(), "boom")
}

func TestServerStreamingReturnsMultipleResponses(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	resp := client.Invoke(streamingMethod, `{"responseParameters": [{"size": 1}, {"size": 2}, {"size": 3}]}`)
	require.Equal(t, 3, strings.Count(resp, "payload"))
}

func TestListMethodsForTestService(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	methods := client.ListMethods("grpc.testing.TestService")
	require.Contains(t, methods, "grpc.testing.TestService.UnaryCall")
	require.Contains(t, methods, "grpc.testing.TestService.EmptyCall")
	require.Contains(t, methods, "grpc.testing.TestService.StreamingOutputCall")
}

func TestDescribeMessageType(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true})
	require.NoError(t, err)

	text := client.DescribeSymbol("grpc.testing.SimpleRequest")
	require.Contains(t, text, "SimpleRequest")
	require.Contains(t, text, "response_size")
}

func TestUnaryCallViaProtoset(t *testing.T) {
	addr := startTestService(t, nil)
	templatesDir := setTemplateDir(t)
	executionID := initExec(t, &types.Options{AllowLocalFileAccess: false})

	protosetPath := filepath.Join(templatesDir, "test.protoset")
	require.NoError(t, os.WriteFile(protosetPath, marshalDescriptorSet(t, grpc_testing.File_grpc_testing_test_proto), 0o600))

	client, err := newRuntimeClient(t, executionID, addr, Options{Plaintext: true, ProtosetFile: protosetPath})
	require.NoError(t, err)

	resp := client.Invoke(unaryMethod, `{"responseSize": 2, "fillOauthScope": true}`)
	require.Contains(t, resp, "test-scope")
}

func TestInvokeRejectsMalformedRequestJSON(t *testing.T) {
	addr := startTestService(t, nil)
	executionID := initExec(t, &types.Options{})

	cc, err := dialTarget(context.Background(), executionID, addr, connConfig{plaintext: true})
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	src, cleanup, err := descriptorSource(context.Background(), executionID, cc, "")
	require.NoError(t, err)
	defer cleanup()

	_, err = invokeUnary(context.Background(), src, cc, unaryMethod, `{"responseSize": `, nil)
	require.Error(t, err)
}

func TestInvokeOverTLS(t *testing.T) {
	cert := selfSignedCert(t)
	addr := startTestService(t, cert)
	executionID := initExec(t, &types.Options{})

	client, err := newRuntimeClient(t, executionID, addr, Options{InsecureSkipVerify: true})
	require.NoError(t, err)

	resp := client.Invoke(unaryMethod, `{"fillOauthScope": true}`)
	require.Contains(t, resp, "test-scope")
}
