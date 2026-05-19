package dcerpc

import (
	"context"
	"net"
	"time"

	gpwmiexec "github.com/Mzack9999/goimpacket/pkg/wmiexec"
	"github.com/oiweiwei/go-msrpc/dcerpc"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// WmiExecResult is returned by WmiExec.
type WmiExecResult struct {
	ReturnValue uint32 `json:"return_value"`
	Output      string `json:"output"`
}

// WmiExec executes a Windows command on the target host using DCOM
// Win32_Process.Create over the WMI IWbemServices interface (impacket:
// wmiexec.py). The command is launched as a fresh process by the WMI host
// process and its stdout/stderr is redirected into a temp file on the chosen
// share (default ADMIN$) which is then read back over SMB. WmiExec is
// stealthier than SmbExec / AtExec because it does not create a service or a
// scheduled task, but Win32_Process.Create itself does not return any captured
// output - the file-tailing roundtrip is required to recover stdout.
//
// The DCOM bootstrap, NTLM/SPNEGO negotiation and Win32_Process.Create call
// live in goimpacket's pkg/wmiexec library; this wrapper only handles the
// JS-facing validation, the per-execution network policy enforcement, and
// wires nuclei's fastdialer into go-msrpc.
//
// command - the command line to run; wrapped in cmd.exe /Q /c by default.
// share   - writable share to retrieve the output file from (default "ADMIN$").
//
// Authentication: NTLM with password or pass-the-hash via SetHash. Kerberos is
// not yet supported on this code path.
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const r = c.WmiExec('whoami /all', 'ADMIN$');
// log(r.output);
// ```
func (c *Client) WmiExec(command, share string) (*WmiExecResult, error) {
	c.nj.Require(command != "", "command cannot be empty")
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	if err := c.connect(); err != nil {
		return nil, err
	}

	target := c.target
	target.Host = c.Host
	target.IP = c.Host

	res, err := gpwmiexec.Exec(
		context.Background(),
		target,
		c.creds,
		command,
		gpwmiexec.Options{Share: share, Timeout: 15 * time.Second},
		gpwmiexec.DialOptions{
			Dialer: &execDialerAdapter{execID: c.nj.ExecutionId()},
			SMB:    c.smb,
		},
	)
	if err != nil {
		return nil, err
	}
	return &WmiExecResult{ReturnValue: res.ReturnValue, Output: res.Output}, nil
}

// execDialerAdapter routes go-msrpc's TCP dials through nuclei's per-execution
// fastdialer. Implements the dcerpc.Dialer interface (DialContext only).
type execDialerAdapter struct{ execID string }

func (e *execDialerAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialWithExec(ctx, e.execID, network, address)
}

// Compile-time guard that execDialerAdapter satisfies dcerpc.Dialer.
var _ dcerpc.Dialer = (*execDialerAdapter)(nil)
