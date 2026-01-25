

/**
 * IsRsync checks if a host is running a Rsync server.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const isRsync = rsync.IsRsync('acme.com', 873);
 * log(toJSON(isRsync));
 * ```
 */
export function IsRsync(ctx: any, host: string, port: number): IsRsyncResponse | null {
    return null;
}



/**
 * RsyncClient is a client for RSYNC servers.
 * Internally client uses https://github.com/gokrazy/rsync driver.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const client = new rsync.RsyncClient();
 * ```
 */
export class RsyncClient {
    

    // Constructor of RsyncClient
    constructor() {}
    /**
    * ListModules lists the modules of a Rsync server.
    * @example
    * ```javascript
    * const rsync = require('nuclei/rsync');
    * const client = new rsync.RsyncClient();
    * const listModules = client.ListModules('acme.com', 873, 'username', 'password');
    * log(toJSON(listModules));
    * ```
    */
    public ListModules(ctx: any, host: string, port: number, username: string, password: string): RsyncListResponse | null {
        return null;
    }
    

    /**
    * ListShares lists the shares of a Rsync server.
    * @example
    * ```javascript
    * const rsync = require('nuclei/rsync');
    * const client = new rsync.RsyncClient();
    * const listShares = client.ListFilesInModule('acme.com', 873, 'username', 'password', '/');
    * log(toJSON(listShares));
    * ```
    */
    public ListFilesInModule(ctx: any, host: string, port: number, username: string, password: string, module: string): RsyncListResponse | null {
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



/**
 * ListSharesResponse is the response from the ListShares function.
 * this is returned by ListShares function.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const client = new rsync.RsyncClient();
 * const listShares = client.ListShares('acme.com', 873);
 * log(toJSON(listShares));
 */
export interface RsyncListResponse {
    
    Modules?: string[],
    
    Files?: string[],
    
    Output?: string,
}

