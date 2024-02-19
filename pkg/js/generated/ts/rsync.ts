

/**
 * RsyncClient is a minimal Rsync client for nuclei scripts.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const client = new rsync.Client();
 * ```
 */
export class RsyncClient {
    

    // Constructor of RsyncClient
    constructor() {}
    /**
    * IsRsync checks if a host is running a Rsync server.
    * @example
    * ```javascript
    * const rsync = require('nuclei/rsync');
    * const isRsync = rsync.IsRsync('acme.com', 873);
    * log(toJSON(isRsync));
    * ```
    */
    public IsRsync(host: string, port: number): IsRsyncResponse | null {
        return null;
    }
    

}



/**
 * IsRsyncResponse is the response from the IsRsync function.
 * this is returned by IsRsync function.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const isRsync = rsync.IsRsync('acme.com', 873);
 * log(toJSON(isRsync));
 * ```
 */
export interface IsRsyncResponse {
    
    IsRsync?: boolean,
    
    Banner?: string,
}

