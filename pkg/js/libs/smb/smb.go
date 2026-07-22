// Package smb exposes the nuclei JavaScript `nuclei/smb` module.
//
// Capability map (nmap SMB scripts → JS API):
//
//	smb-protocols     → SMBClient.ListProtocols / ConnectSMBInfoMode
//	smb-ls            → SMBClient.ListDir / ListTree
//	(file read/cat)   → SMBClient.ReadFile
//	share enum        → SMBClient.ListShares
//	SMBGhost check    → SMBClient.DetectSMBGhost
//
// Authenticated share I/O is backed by pkg/js/libs/smbsession (goimpacket) so
// nuclei/smb and nuclei/dcerpc.SmbLs/SmbCat share one stack. Unauthenticated
// discovery still uses zgrab2 / fingerprintx.
//
// RPC-heavy nmap scripts (enum-users/services/sessions/processes, psexec) live under
// `nuclei/dcerpc` / `nuclei/goexec` — see that package's docs. Do not duplicate
// them here; share filesystem and unauthenticated discovery stay in this module.
//
// Permanently out of scope for nuclei (also documented on dcerpc):
// smb-flood (DoS), smb-mbenum (obsolete browser), smb-print-text (printer write).
//
// Sandbox rules applied to every share operation:
//   - protocolstate.IsHostAllowed before dial
//   - fastdialer only (via gptransport)
//   - share-relative paths; ".." escapes rejected
//   - ReadFile capped (default 10 MiB); ListTree depth/entry capped
package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

type (
	// SMBClient is a client for SMB servers.
	// Unauthenticated discovery uses zgrab2 / fingerprintx.
	// Authenticated share I/O uses goimpacket via pkg/js/libs/smbsession.
	// @example
	// ```javascript
	// const smb = require('nuclei/smb');
	// const client = new smb.SMBClient();
	// ```
	SMBClient struct{}

	// ProtocolInfo summarises dialects and capabilities discovered during
	// SMB negotiation (nmap smb-protocols style).
	// @example
	// ```javascript
	// const smb = require('nuclei/smb');
	// const client = new smb.SMBClient();
	// const info = client.ListProtocols('acme.com', 445);
	// log(to_json(info));
	// ```
	ProtocolInfo struct {
		SMB1Supported bool   `json:"smb1_supported"`
		SMB2Supported bool   `json:"smb2_supported"`
		Version       string `json:"version,omitempty"`
		Dialect       string `json:"dialect,omitempty"`
		HasNTLM       bool   `json:"has_ntlm"`
		NativeOS      string `json:"native_os,omitempty"`
		NTLM          string `json:"ntlm,omitempty"`
		GroupName     string `json:"group_name,omitempty"`
	}
)

// ConnectSMBInfoMode tries to connect to provided host and port
// and discovery SMB information
// Returns handshake log and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const info = client.ConnectSMBInfoMode('acme.com', 445);
// log(to_json(info));
// ```
func (c *SMBClient) ConnectSMBInfoMode(ctx context.Context, host string, port int) (*smb.SMBLog, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnectSMBInfoMode(ctx, executionId, host, port)
}

// @memo
func connectSMBInfoMode(ctx context.Context, executionId string, host string, port int) (*smb.SMBLog, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialSMBInfo := func(ctx context.Context) (net.Conn, error) {
		return dialer.Fastdialer.Dial(ctx, "tcp", address)
	}
	conn, err := dialSMBInfo(ctx)
	if err != nil {
		return nil, err
	}
	// try to get SMBv2/v3 info
	result, err := getSMBInfo(conn, true, false)
	_ = conn.Close() // close regardless of error
	if err == nil {
		updateSMBv1Support(ctx, result, dialSMBInfo)
		return result, nil
	}

	// try to negotiate SMBv1
	conn, err = dialSMBInfo(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()
	result, err = getSMBInfo(conn, true, true)
	if err != nil {
		return result, nil
	}
	return result, nil
}

// ListSMBv2Metadata tries to connect to provided host and port
// and list SMBv2 metadata.
// Returns metadata and error. If error is not nil,
// state will be false
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const metadata = client.ListSMBv2Metadata('acme.com', 445);
// log(to_json(metadata));
// ```
func (c *SMBClient) ListSMBv2Metadata(ctx context.Context, host string, port int) (*plugins.ServiceSMB, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	return memoizedcollectSMBv2Metadata(ctx, executionId, host, port, 5*time.Second)
}

// ListShares tries to connect to provided host and port
// and list shares by using given credentials.
// Credentials cannot be blank. guest or anonymous credentials
// can be used by providing empty password.
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const shares = client.ListShares('acme.com', 445, 'username', 'password');
//
//	for (const share of shares) {
//		  log(share);
//	}
//
// ```
func (c *SMBClient) ListShares(ctx context.Context, host string, port int, user, password string) ([]string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedlistShares(ctx, executionId, host, port, user, password)
}

// ListDir lists files and directories under path on the given share
// (nmap smb-ls). path may be empty or "." for the share root.
// user may be "DOMAIN\\user" or "user@domain".
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const entries = client.ListDir('acme.com', 445, 'user', 'pass', 'backup', '.');
// for (const e of entries) { log(e.Name + (e.IsDir ? '/' : '')); }
// ```
func (c *SMBClient) ListDir(ctx context.Context, host string, port int, user, password, share, dir string) ([]ShareEntry, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedlistDir(ctx, executionId, host, port, user, password, share, dir)
}

// ReadFile reads a file from share/path into a string, capped at 10 MiB
// (nmap smb-ls / smb-cat style content fetch).
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const body = client.ReadFile('acme.com', 445, 'user', 'pass', 'backup', 'creds.txt');
// log(body);
// ```
func (c *SMBClient) ReadFile(ctx context.Context, host string, port int, user, password, share, filePath string) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedreadFile(ctx, executionId, host, port, user, password, share, filePath)
}

// ListTree recursively lists files under path on share up to a fixed depth
// and entry budget. Entry names are share-relative paths.
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const tree = client.ListTree('acme.com', 445, 'user', 'pass', 'backup', '.');
// for (const e of tree) { log(e.Name); }
// ```
func (c *SMBClient) ListTree(ctx context.Context, host string, port int, user, password, share, dir string) ([]ShareEntry, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedlistTree(ctx, executionId, host, port, user, password, share, dir)
}

// ListProtocols discovers which SMB dialects/capabilities the server
// exposes (nmap smb-protocols).
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const info = client.ListProtocols('acme.com', 445);
// log(to_json(info));
// ```
func (c *SMBClient) ListProtocols(ctx context.Context, host string, port int) (*ProtocolInfo, error) {
	log, err := c.ConnectSMBInfoMode(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return protocolInfoFromLog(log), nil
}

func protocolInfoFromLog(log *smb.SMBLog) *ProtocolInfo {
	if log == nil {
		return &ProtocolInfo{}
	}
	info := &ProtocolInfo{
		SMB1Supported: log.SupportV1,
		HasNTLM:       log.HasNTLM,
		NativeOS:      log.NativeOs,
		NTLM:          log.NTLM,
		GroupName:     log.GroupName,
	}
	if log.Version != nil {
		info.Version = log.Version.VerString
		if log.Version.Major >= 2 {
			info.SMB2Supported = true
		}
		if log.Version.Major == 1 {
			info.SMB1Supported = true
		}
	}
	if log.NegotiationLog != nil {
		info.Dialect = dialectName(log.NegotiationLog.DialectRevision)
		if log.NegotiationLog.DialectRevision != 0 && log.NegotiationLog.DialectRevision != smb.DialectSmb2_ALL {
			info.SMB2Supported = true
		}
	}
	// ConnectSMBInfoMode returns a usable log when SMBv2/v3 negotiated.
	if !info.SMB1Supported && !info.SMB2Supported && info.Version != "" {
		info.SMB2Supported = true
	}
	return info
}

func dialectName(rev uint16) string {
	switch rev {
	case smb.DialectSmb_2_0_2:
		return "SMB 2.0.2"
	case smb.DialectSmb_2_1:
		return "SMB 2.1"
	case smb.DialectSmb_3_0:
		return "SMB 3.0"
	case smb.DialectSmb_3_0_2:
		return "SMB 3.0.2"
	case smb.DialectSmb_3_1_1:
		return "SMB 3.1.1"
	case smb.DialectSmb2_ALL:
		return "SMB 2+/wildcard"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", rev)
	}
}
