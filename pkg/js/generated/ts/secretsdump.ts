

/**
 * Client wraps an authenticated session to a Domain Controller and exposes
 * DCSync helpers.
 * @example
 * ```javascript
 * const sd = require('nuclei/secretsdump');
 * const c = new sd.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ss');
 * const krbtgt = c.DCSync('krbtgt');
 * ExportAs('krbtgt_nthash', krbtgt.nthash);
 * ```
 */
export class Client {
    

    
    public Host?: string;
    

    
    public Domain?: string;
    

    
    public User?: string;
    

    
    public Pass?: string;
    

    // Constructor of Client
    constructor(public dc: string, public domain: string, public user: string, public password: string ) {}
    

    /**
    * SetHash enables NTLM pass-the-hash authentication.
    * @example
    * ```javascript
    * const c = new sd.Client('dc01', 'acme.local', 'admin', '');
    * c.SetHash(':31d6cfe0d16ae931b73c59d7e0c089c0');
    * ```
    */
    public SetHash(hash: string): void {
        return;
    }
    

    /**
    * DCSync replicates secrets for a single principal (DN, sAMAccountName, or
    * SID) and returns its NT/LM hashes, hash history and account state.
    * @example
    * ```javascript
    * const sd = require('nuclei/secretsdump');
    * const c = new sd.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const s = c.DCSync('Administrator');
    * log(s.nthash);
    * ```
    */
    public DCSync(target: string): Secret | null {
        return null;
    }
    

}



/**
 * Secret is the result of a DCSync against a single principal.
 */
export interface Secret {
    
    sam_account_name?: string,
    
    distinguished_name?: string,
    
    rid?: number,
    
    nthash?: string,
    
    lmhash?: string,
    
    nthash_history?: string[],
    
    lmhash_history?: string[],
    
    user_account_control?: number,
    
    pwd_last_set?: number,
}

