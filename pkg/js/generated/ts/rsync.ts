

/**
 * IsRsync checks if a host is running a Rsync server.
 * @example
 * ```javascript
 * const rsync = require('nuclei/rsync');
 * const isRsync = rsync.IsRsync('acme.com', 873);
 * log(toJSON(isRsync));
 * ```
 */
export function IsRsync(host: string, port: number): IsRsyncResponse | null {
    return null;
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

