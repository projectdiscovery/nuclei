package grpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/fullstorydev/grpcurl"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// connConfig holds the low level knobs used to build a gRPC client connection.
// It is intentionally decoupled from the JS-facing Options struct so the dial
// logic stays independently testable.
type connConfig struct {
	plaintext          bool
	insecureSkipVerify bool
	serverName         string
	maxRecvMsgSize     int
}

// dialTarget builds a *grpc.ClientConn whose every connection is routed through
// nuclei's network policy. The host is validated up front and the actual dial
// is delegated to the execution's fastdialer via a custom context dialer, so
// IP/host denylists and RestrictLocalNetworkAccess are always enforced. The
// passthrough scheme guarantees the target is handed verbatim to our dialer
// (instead of gRPC's built in DNS resolver), keeping resolution and policy
// enforcement inside fastdialer.
func dialTarget(ctx context.Context, executionID, target string, cfg connConfig) (*grpc.ClientConn, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid grpc target %q (expected host:port): %w", target, err)
	}
	if host == "" {
		return nil, fmt.Errorf("grpc target host cannot be empty")
	}
	if executionID == "" {
		return nil, fmt.Errorf("grpc: refusing to dial without executionId")
	}
	if !protocolstate.IsHostAllowed(executionID, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialers := protocolstate.GetDialersWithId(executionID)
	if dialers == nil || dialers.Fastdialer == nil {
		return nil, fmt.Errorf("grpc: dialers not initialized for executionId %q", executionID)
	}

	contextDialer := func(dialCtx context.Context, addr string) (net.Conn, error) {
		return dialers.Fastdialer.Dial(dialCtx, "tcp", addr)
	}

	var creds credentials.TransportCredentials
	if cfg.plaintext {
		creds = insecure.NewCredentials()
	} else {
		serverName := cfg.serverName
		if serverName == "" {
			serverName = host
		}
		creds = credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: cfg.insecureSkipVerify,
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS12,
		})
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(contextDialer),
	}
	if cfg.maxRecvMsgSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(cfg.maxRecvMsgSize)))
	}
	_ = ctx // reserved for future dial-time hooks; connection is established lazily
	return grpc.NewClient("passthrough:///"+target, opts...)
}

// descriptorSource resolves the gRPC method/message schema either from a local
// compiled protoset file (read through the local-file-access allowlist) or, when
// no protoset is provided, from server reflection over the existing connection.
// The returned cleanup func must be called once the source is no longer needed.
func descriptorSource(ctx context.Context, executionID string, cc *grpc.ClientConn, protosetFile string) (grpcurl.DescriptorSource, func(), error) {
	noop := func() {}
	if strings.TrimSpace(protosetFile) != "" {
		// resolve through the local-file-access allowlist: unless -lfa is set,
		// only files inside the nuclei-templates directory are permitted.
		normalized, err := protocolstate.NormalizePathWithExecutionId(executionID, protosetFile)
		if err != nil {
			return nil, noop, fmt.Errorf("protoset path denied: %w", err)
		}
		data, err := os.ReadFile(normalized)
		if err != nil {
			return nil, noop, fmt.Errorf("failed to read protoset file: %w", err)
		}
		fds := &descriptorpb.FileDescriptorSet{}
		if err := proto.Unmarshal(data, fds); err != nil {
			return nil, noop, fmt.Errorf("failed to parse protoset file: %w", err)
		}
		src, err := grpcurl.DescriptorSourceFromFileDescriptorSet(fds)
		if err != nil {
			return nil, noop, fmt.Errorf("failed to build descriptor source from protoset: %w", err)
		}
		return src, noop, nil
	}

	refClient := grpcreflect.NewClientAuto(ctx, cc)
	cleanup := func() { refClient.Reset() }
	return grpcurl.DescriptorSourceFromServer(ctx, refClient), cleanup, nil
}

// invokeUnary invokes a unary (or single-response) gRPC method described by src
// over cc, marshaling the JSON request and formatting the JSON response.
func invokeUnary(ctx context.Context, src grpcurl.DescriptorSource, cc *grpc.ClientConn, method, requestJSON string, headers []string) (string, error) {
	body := strings.TrimSpace(requestJSON)
	if body == "" {
		body = "{}"
	}
	var in io.Reader = strings.NewReader(body)

	parser, formatter, err := grpcurl.RequestParserAndFormatter(grpcurl.FormatJSON, src, in, grpcurl.FormatOptions{
		EmitJSONDefaultFields: true,
		AllowUnknownFields:    false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to build request parser: %w", err)
	}

	var out bytes.Buffer
	handler := &grpcurl.DefaultEventHandler{
		Out:       &out,
		Formatter: formatter,
	}

	if err := grpcurl.InvokeRPC(ctx, src, cc, method, headers, handler, parser.Next); err != nil {
		return "", err
	}
	if handler.Status != nil && handler.Status.Code() != codes.OK {
		return "", fmt.Errorf("grpc status %s: %s", handler.Status.Code().String(), handler.Status.Message())
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

// describeSymbol returns the textual descriptor for a fully-qualified symbol.
func describeSymbol(src grpcurl.DescriptorSource, symbol string) (string, error) {
	dsc, err := src.FindSymbol(symbol)
	if err != nil {
		return "", err
	}
	return grpcurl.GetDescriptorText(dsc, src)
}
