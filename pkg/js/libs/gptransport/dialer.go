// Package gptransport binds Mzack9999/goimpacket TCP dials to nuclei's
// per-execution fastdialer and network policy.
//
// Import this package (directly or via smbsession / dcerpc) so init() installs
// the global tripwire: any goimpacket dial without an execution-bound Dialer
// fails closed instead of leaking across scans.
package gptransport

import (
	"context"
	"fmt"
	"net"

	gptr "github.com/Mzack9999/goimpacket/pkg/transport"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func init() {
	gptr.SetDial(func(ctx context.Context, network, address string) (net.Conn, error) {
		execID := ExecutionIDFromCtx(ctx)
		if execID == "" {
			return nil, fmt.Errorf("goimpacket: refusing to dial %s/%s without an executionId-bound dialer; wrap the call site with a *gptransport.Dialer built via NewExecDialer", network, address)
		}
		return DialWithExec(ctx, execID, network, address)
	})
}

// NewExecDialer returns a *gptr.Dialer whose DialFn is bound to the
// given executionId. Every connection made through the returned dialer is
// validated against the execution's network policy and routed through the
// matching fastdialer.
func NewExecDialer(execID string) *gptr.Dialer {
	if execID == "" {
		return &gptr.Dialer{}
	}
	return &gptr.Dialer{
		DialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return DialWithExec(ctx, execID, network, address)
		},
	}
}

// DialWithExec performs the fastdialer dial after enforcing host policy.
func DialWithExec(ctx context.Context, execID, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if !protocolstate.IsHostAllowed(execID, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialer := protocolstate.GetDialersWithId(execID)
	if dialer == nil || dialer.Fastdialer == nil {
		return nil, fmt.Errorf("goimpacket: no fastdialer registered for executionId %q", execID)
	}
	return dialer.Fastdialer.Dial(ctx, network, address)
}

// ExecutionIDFromCtx pulls the executionId set by nuclei on its goja runtime
// or scan context. Returns "" when the context carries no id.
func ExecutionIDFromCtx(ctx context.Context) string {
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
