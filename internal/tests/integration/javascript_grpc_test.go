//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// startGRPCHealthServer starts an in-process gRPC server exposing the standard
// health service (status SERVING) and server reflection on a random loopback
// port. It returns the "host:port" address and a stop func.
func startGRPCHealthServer() (string, func(), error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("grpc health listen: %w", err)
	}
	srv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	reflection.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), srv.Stop, nil
}

// javascriptGRPCHealth exercises the nuclei/grpc library end to end against a
// real gRPC server via server reflection.
type javascriptGRPCHealth struct{}

func (j *javascriptGRPCHealth) Execute(filePath string) error {
	address, stop, err := startGRPCHealthServer()
	if err != nil {
		return err
	}
	defer stop()

	results, err := runSignedNucleiTemplateAndGetResults(filePath, address, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// javascriptGRPCDenied asserts the nuclei/grpc library refuses to dial a host
// on the exclude list (network-policy enforcement) before connecting.
type javascriptGRPCDenied struct{}

func (j *javascriptGRPCDenied) Execute(filePath string) error {
	results, err := runSignedNucleiTemplateAndGetResults(filePath, "127.0.0.1", debug, "-eh", "203.0.113.10")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
