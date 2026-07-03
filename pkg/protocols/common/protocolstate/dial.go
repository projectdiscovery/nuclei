package protocolstate

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// ExecutionIDFromContext returns the nuclei execution id stored on ctx.
func ExecutionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v := ctx.Value("executionId"); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// DialAllowed dials through the execution-scoped fastdialer which enforces
// network policy. All javascript/code native modules must use this helper
// instead of calling net.Dial or Fastdialer directly.
func DialAllowed(ctx context.Context, network, address string) (net.Conn, error) {
	executionID := ExecutionIDFromContext(ctx)
	if executionID == "" {
		return nil, fmt.Errorf("protocolstate: refusing to dial %s/%s without executionId", network, address)
	}
	return DialAllowedWithExecutionID(ctx, executionID, network, address)
}

// DialAllowedWithExecutionID dials using a known execution id.
func DialAllowedWithExecutionID(ctx context.Context, executionID, network, address string) (net.Conn, error) {
	if executionID == "" {
		return nil, fmt.Errorf("protocolstate: refusing to dial %s/%s without executionId", network, address)
	}
	dialer := GetDialersWithId(executionID)
	if dialer == nil || dialer.Fastdialer == nil {
		return nil, fmt.Errorf("protocolstate: dialers not initialized for %q", executionID)
	}
	return dialer.Fastdialer.Dial(ctx, network, address)
}

// DialTLSAllowed dials TLS through the execution-scoped fastdialer.
func DialTLSAllowed(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
	executionID := ExecutionIDFromContext(ctx)
	if executionID == "" {
		return nil, fmt.Errorf("protocolstate: refusing to dial %s/%s without executionId", network, address)
	}
	return DialTLSAllowedWithExecutionID(ctx, executionID, network, address, config)
}

// DialTLSAllowedWithExecutionID dials TLS using a known execution id.
func DialTLSAllowedWithExecutionID(ctx context.Context, executionID, network, address string, config *tls.Config) (net.Conn, error) {
	if executionID == "" {
		return nil, fmt.Errorf("protocolstate: refusing to dial %s/%s without executionId", network, address)
	}
	dialer := GetDialersWithId(executionID)
	if dialer == nil || dialer.Fastdialer == nil {
		return nil, fmt.Errorf("protocolstate: dialers not initialized for %q", executionID)
	}
	return dialer.Fastdialer.DialTLSWithConfig(ctx, network, address, config)
}
