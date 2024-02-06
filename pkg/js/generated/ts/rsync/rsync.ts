

/**
 * RsyncClient Class
 */
export class RsyncClient {
    

    // Constructor of RsyncClient
    constructor() {}
    /**
    * IsRsync checks if a host is running a Rsync server.
    * @throws {Error} - if the operation fails
    */
    public IsRsync(host: string, port: number): IsRsyncResponse | null {
        return null;
    }
    

}



/**
 * IsRsyncResponse interface
 */
export interface IsRsyncResponse {
    
    IsRsync?: boolean,
    
    Banner?: string,
}

