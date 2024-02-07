

/**
 * Pop3Client is a minimal POP3 client for nuclei scripts.
 * @example
 * ```javascript
 * const pop3 = require('nuclei/pop3');
 * const client = new pop3.Client();
 * ```
 */
export class Pop3Client {
    

    // Constructor of Pop3Client
    constructor() {}
    /**
    * IsPOP3 checks if a host is running a POP3 server.
    * @example
    * ```javascript
    * const pop3 = require('nuclei/pop3');
    * const isPOP3 = pop3.IsPOP3('acme.com', 110);
    * log(toJSON(isPOP3));
    * ```
    */
    public IsPOP3(host: string, port: number): IsPOP3Response | null {
        return null;
    }
    

}



/**
 * IsPOP3Response is the response from the IsPOP3 function.
 * this is returned by IsPOP3 function.
 * @example
 * ```javascript
 * const pop3 = require('nuclei/pop3');
 * const isPOP3 = pop3.IsPOP3('acme.com', 110);
 * log(toJSON(isPOP3));
 * ```
 */
export interface IsPOP3Response {
    
    IsPOP3?: boolean,
    
    Banner?: string,
}

