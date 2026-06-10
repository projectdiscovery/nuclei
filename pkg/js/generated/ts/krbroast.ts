

/**
 * ASRepRoast asks the KDC for the AS-REP of a user that has DONT_REQ_PREAUTH
 * set. No credentials are required. Returns the cracking-format string or
 * throws if the user requires pre-auth or does not exist.
 * Implemented as a goja-native function so the calling runtime's executionId
 * can be captured and bound into the *transport.Dialer routed to the KDC.
 * @example
 * ```javascript
 * const krb = require('nuclei/krbroast');
 * 	const hash = krb.ASRepRoast({
 * 	  Username: 'svc_jenkins',
 * 	  Domain:   'acme.local',
 * 	  KDCHost:  'dc01.acme.local',
 * 	});
 * log(hash);
 * ```
 */
export function ASRepRoast(call: any, vm: any): goja.Value {
    return new goja.Value();
}



/**
 * Kerberoast requests a TGS for the given SPN using the supplied credentials
 * and returns its hashcat-formatted hash for offline cracking.
 * Note: the underlying jcmturner/gokrb5 client used by GetTGSWithOptions
 * performs its own net.Dial that is not routed through nuclei's fastdialer.
 * The host is still pre-validated against the per-execution network policy so
 * allowlist / denylist constraints are enforced before any traffic is sent.
 * @example
 * ```javascript
 * const krb = require('nuclei/krbroast');
 * 	const r = krb.Kerberoast({
 * 	  Username:   'lowpriv',
 * 	  Password:   'P@ss',
 * 	  Domain:     'acme.local',
 * 	  KDCHost:    'dc01.acme.local',
 * 	  SPN:        'MSSQLSvc/sql01.acme.local:1433',
 * 	  TargetUser: 'svc_sql',
 * 	});
 * log(r.Hash);
 * ```
 */
export function Kerberoast(call: any, vm: any): goja.Value {
    return new goja.Value();
}



/**
 */
export interface ASRepRoastRequest {
    
    Username?: string,
    
    Domain?: string,
    
    KDCHost?: string,
    
    Format?: string,
}



/**
 */
export interface KerberoastRequest {
    
    Username?: string,
    
    Password?: string,
    
    NTHash?: string,
    
    Domain?: string,
    
    KDCHost?: string,
    
    SPN?: string,
    
    TargetUser?: string,
}



/**
 */
export interface KerberoastResult {
    
    Username?: string,
    
    SPN?: string,
    
    Hash?: string,
    
    EType?: number,
}

