

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
     * Connect establishes a connection to the rsync server with authentication.
     * @example
     * ```javascript
     * const rsync = require('nuclei/rsync');
     * const client = new rsync.RsyncClient();
     * const connected = client.Connect('acme.com', 873, 'username', 'password', 'backup');
     * ```
     */
    public Connect(host: string, port: number, username: string, password: string, module: string): boolean | null {
        return null;
    }
    
    /**
     * ListModules lists available modules on the rsync server.
     * @example
     * ```javascript
     * const rsync = require('nuclei/rsync');
     * const client = new rsync.RsyncClient();
     * const modules = client.ListModules('acme.com', 873, 'username', 'password');
     * log(toJSON(modules));
     * ```
     */
    public ListModules(host: string, port: number, username: string, password: string): string[] | null {
        return null;
    }
    
    /**
     * ListFilesInModule lists files in a specific module on the rsync server.
     * @example
     * ```javascript
     * const rsync = require('nuclei/rsync');
     * const client = new rsync.RsyncClient();
     * const files = client.ListFilesInModule('acme.com', 873, 'username', 'password', 'backup');
     * log(toJSON(files));
     * ```
     */
    public ListFilesInModule(host: string, port: number, username: string, password: string, module: string): string[] | null {
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

