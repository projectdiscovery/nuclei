package dcerpc

import (
	"context"
	"fmt"
	"net"

	gptransport "github.com/Mzack9999/goimpacket/pkg/transport"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// init wires the goimpacket package-level dial hook as a strict tripwire.
// Every TCP connection inside goimpacket is supposed to go through a
// per-Client *gptransport.Dialer built by NewExecDialer below, which captures
// the executionId of the calling JS runtime. If something inside goimpacket
// bypasses that and reaches this global hook we refuse to dial - we will not
// silently pick a random execution's dialer.
func init() {
	gptransport.SetDial(func(ctx context.Context, network, address string) (net.Conn, error) {
		execID := executionIDFromCtx(ctx)
		if execID == "" {
			return nil, fmt.Errorf("goimpacket: refusing to dial %s/%s without an executionId-bound dialer; wrap the call site with a *gptransport.Dialer built via NewExecDialer", network, address)
		}
		return dialWithExec(ctx, execID, network, address)
	})
}

// NewExecDialer returns a *gptransport.Dialer whose DialFn is bound to the
// given executionId. Every connection made through the returned dialer is
// validated against the execution's network policy and routed through the
// matching fastdialer. Pass it into goimpacket constructors such as
// smb.NewClientWithDialer or dcerpc.DialTCPWithDialer to guarantee the
// connection cannot leak across executions.
func NewExecDialer(execID string) *gptransport.Dialer {
	if execID == "" {
		return &gptransport.Dialer{}
	}
	return &gptransport.Dialer{
		DialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialWithExec(ctx, execID, network, address)
		},
	}
}

// dialWithExec performs the actual fastdialer dial after enforcing the
// per-execution host policy.
func dialWithExec(ctx context.Context, execID, network, address string) (net.Conn, error) {
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

// executionIDFromCtx pulls the executionId set by nuclei on its goja runtime
// or scan context. Returns "" when the context carries no id.
func executionIDFromCtx(ctx context.Context) string {
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
