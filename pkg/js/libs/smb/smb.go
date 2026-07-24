package smb

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/go-smb2"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

type (
	// SMBClient is a client for SMB servers.
	// Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
	// github.com/projectdiscovery/go-smb2 driver
	// @example
	// ```javascript
	// const smb = require('nuclei/smb');
	// const client = new smb.SMBClient();
	// ```
	SMBClient struct{}
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
//
// Deprecated: prefer ListSharesWithOptions for new templates.
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

type (
	// SMBOptions represents configuration for authenticated SMB operations.
	// @example
	// ```javascript
	// const smb = require('nuclei/smb');
	// const client = new smb.SMBClient();
	// const opts = new smb.SMBOptions();
	// opts.Host = 'acme.com';
	// opts.Port = 445;
	// opts.User = 'Administrator';
	// opts.Password = 'password';
	// opts.Domain = 'ACME';
	// const shares = client.ListSharesWithOptions(opts);
	// ```
	SMBOptions struct {
		Host        string // Host is the hostname or IP of the SMB server.
		Port        int    // Port is the SMB port (usually 445).
		User        string // User is the username for NTLM authentication.
		Password    string // Password is the password for NTLM authentication.
		Hash        string // Hash is an optional hex-encoded NTLM hash (pass-the-hash).
		Domain      string // Domain is the NTLM domain / workgroup.
		Workstation string // Workstation is the NTLM workstation name.
		TargetSPN   string // TargetSPN overrides the NTLM target SPN.
		Timeout     int    // Timeout is the dial timeout in seconds (default 10).
	}
)

// ListSharesWithOptions lists SMB share names using SMBOptions.
// Supports domain, pass-the-hash, workstation, and SPN overrides.
// @example
// ```javascript
// const smb = require('nuclei/smb');
// const client = new smb.SMBClient();
// const opts = new smb.SMBOptions();
// opts.Host = 'acme.com';
// opts.Port = 445;
// opts.User = 'Administrator';
// opts.Hash = 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0';
// opts.Domain = 'ACME';
// const shares = client.ListSharesWithOptions(opts);
// ```
func (c *SMBClient) ListSharesWithOptions(ctx context.Context, opts SMBOptions) ([]string, error) {
	executionId := ctx.Value("executionId").(string)
	return listSharesWithOptions(ctx, executionId, opts)
}

func listSharesWithOptions(ctx context.Context, executionId string, opts SMBOptions) ([]string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, opts.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(opts.Host)
	}
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	timeout := 10 * time.Second
	if opts.Timeout > 0 {
		timeout = time.Duration(opts.Timeout) * time.Second
	}
	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	conn, err := dialer.Fastdialer.Dial(dialCtx, "tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	initiator := &smb2.NTLMInitiator{
		User:        opts.User,
		Password:    opts.Password,
		Domain:      opts.Domain,
		Workstation: opts.Workstation,
		TargetSPN:   opts.TargetSPN,
	}
	if opts.Hash != "" {
		hash, err := decodeNTLMHash(opts.Hash)
		if err != nil {
			return nil, err
		}
		initiator.Hash = hash
	}

	d := &smb2.Dialer{Initiator: initiator}
	s, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = s.Logoff()
	}()

	return s.ListSharenames()
}

func decodeNTLMHash(raw string) ([]byte, error) {
	// Accept LM:NT or bare NT hash hex.
	h := raw
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		h = raw[i+1:]
	}
	decoded, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid ntlm hash: %w", err)
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("invalid ntlm hash length: got %d bytes, want 16", len(decoded))
	}
	return decoded, nil
}

// @memo
func listShares(ctx context.Context, executionId string, host string, port int, user string, password string) ([]string, error) {
	return listSharesWithOptions(ctx, executionId, SMBOptions{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
	})
}
